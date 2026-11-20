# OTLP 尾采样收集器（值班排障用）

接收 OTLP/HTTP JSON，把每条 trace 的 span 先收进 5 秒窗口，窗口结束时做尾采样：
**出错的链、或根 span 耗时超过 500 ms 的链整组留存，其余丢弃**。附带网页，可查看
采样状态与留存的 span，并可模拟"入口先报、下游稍后分批上报"。

## 运行

```bash
docker compose up --build
# 值班页  http://localhost:8000
# 协查页  http://localhost:8080  （仅领取与查看）
```

状态保存在命名卷 `collector-data` 中的 SQLite 文件里；`docker compose restart`
后沿用原截止时间、协查链接有效期、领取与撤回状态，不会重新计时。

Compose 里两个服务共用同一数据卷但只发布各自的页面：`collector` 绑定
`127.0.0.1:8000`（OTLP 接收与内网巡检接口，不对外），`incident` 发布 `8080`
（协查入口，只有领取页和查看接口）。协查进程是独立 FastAPI 应用，不导入也不挂载
采集器任何路由。

本地（无 Docker）运行：

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --port 8000          # 值班页 + OTLP
uvicorn app.incident_app:app --port 8080  # 协查页
```

## 规则（实现语义）

| 规则 | 实现 |
| --- | --- |
| 每条链收集 5 秒 | 从**首次接纳 span 的受理时刻**起固定 5 秒，截止时间不因后续 span 或重启改变 |
| 整组留存的判定 | 窗口内任一已接纳 span 状态为 ERROR，**或**根 span（无 parentSpanId）耗时 > 500 ms |
| 阈值边界 | 根 span 恰好 500 ms 不算慢，丢弃；报错判定不看窗口外或重复上报的 span |
| 并发上限 8 条链 | 只约束"收集中"的链；满额时新 trace 的 span 被拒收，已有链照常补报 |
| 判定与释放名额同时生效 | 判定是一次事务内的 UPDATE；同一事务内先结算到期链再受理新 span，所以名额立即复用 |
| 重复 span 只记一次 | `(trace_id, span_id)` 主键 + `INSERT OR IGNORE`，重复不计入 span 数 |
| 迟到 span 不改判定 | 链一旦变为 kept/dropped，后续 span 一律拒收（OTLP partialSuccess 中返回 rejectedSpans） |
| SQLite 持久化 | 所有状态（含 `first_seen_at`/`deadline_at`）在 SQLite WAL 库中，重启沿用原截止时间 |

后台每 50 ms 结算一次到期链，因此**即使没有新流量**，窗口结束也会按时判定并释放名额。

窗口内已报错的链，即便报错 span 是迟到者（窗口关闭后才到）也不会留存——迟到 span
根本不会被接纳。

## 接口

- `POST /v1/traces` — OTLP/HTTP JSON（`Content-Type: application/json`，支持 gzip）。
  成功返回 `{}`；有 span 被拒时返回 OTLP 规范形状：
  `{"partialSuccess": {"rejectedSpans": N, "errorMessage": "..."}}`（HTTP 200）。
  非 JSON / 结构错误返回 400。
- `GET /api/traces?state=collecting|kept|dropped&limit=50` — 列表 + 状态计数 + 容量。
- `GET /api/traces/{trace_id}` — 单条链的状态、截止时间、判定原因、留存 span。
- `GET /api/config`、`GET /api/stats`、`GET /healthz`。
- 网页：`GET /`；`/?trace=<id>` 可直接打开某条链。

### 协查链接（值班侧，内网）

- `POST /api/incidents/links` `{"trace_id": ..., "service": ...}` — 为**已留存**
  链路中的某个服务签发链接，返回 `link_id`、`expires_at` 和公网 `url`。
- `GET /api/incidents/links?trace_id=...` — 该链路的链接及状态
  （`open` / `claimed` / `revoked` / `expired`）。
- `POST /api/incidents/links/{link_id}/revoke` — 撤回。
- `GET /api/incidents/config` — 有效期与公网基址。

### 协查页（公网独立端口，仅此三条）

- `GET /i/{link_id}` — 领取页（先展示领取页，不展示链路数据）。
- `POST /i/{link_id}/claim` `{"nonce": "..."}` — 领取；并发时只有一个成功。
  令牌写入 `HttpOnly` Cookie，服务端只存哈希。
- `GET /i/{link_id}/view` — 已领取浏览器反复查看所选服务的 span
  **名称、耗时、状态**；不含 span id、属性、原始 OTLP 或其他服务。
- `GET /i/{link_id}/state`、`GET /healthz`。

协查页的 `/v1/traces`、`/api/traces`、`/api/stats` 等采集器接口一律 404。

### 协查语义

| 要求 | 实现 |
| --- | --- |
| 仅已留存链路、单个服务 | 建链时校验 `state=kept` 且服务确有留存 span |
| 签发后 15 分钟内有效 | `expires_at = created_at + INCIDENT_TTL_SECONDS`，固定不改 |
| 打开先显示领取页 | `/i/{id}` 只返回领取页；未领取时 `/state` 不返回 trace_id |
| 只有领取成功的浏览器能查看 | `/view` 校验 Cookie 中的令牌；其他浏览器 401/403 |
| 两个浏览器同时领取只成功一个 | `BEGIN IMMEDIATE` + `UPDATE ... WHERE claimed_at IS NULL` |
| 响应丢失后原浏览器重试仍可查看 | 令牌由 DB 内签名密钥 + 客户端 nonce 派生；同 nonce 重试幂等 |
| 撤回/到期后已领取也不能再取数 | 每次 `/view` 重新校验状态与有效期 |
| 重启保持有效期/领取/撤回 | 全部状态在 SQLite；签名密钥也在库里 |

### 模拟上报

`POST /api/simulate`，body 例：

```json
{"part": "root", "trace_id": null, "root_duration_ms": 80, "root_error": false,
 "downstream_duration_ms": 40, "downstream_error": false}
```

`part` 取 `both`（一次报整条链）、`root`（只报入口）、`downstream`（补报下游；
需带上 `trace_id`，网页会自动带回）。模拟器生成两个服务（`checkout-api` 与
`inventory-svc`），走与 `/v1/traces` 完全相同的解析和入库路径。

## 配置

| 环境变量 | 默认 | 说明 |
| --- | --- | --- |
| `DB_PATH` | `data/collector.db` | SQLite 路径（Compose 中为 `/data/collector.db`） |
| `COLLECT_WINDOW_SECONDS` | `5` | 收集窗口 |
| `MAX_ACTIVE_TRACES` | `8` | 同时收集的链上限 |
| `SLOW_ROOT_MS` | `500` | 慢根阈值（严格大于） |
| `SWEEP_INTERVAL_MS` | `50` | 后台结算间隔 |
| `INCIDENT_TTL_SECONDS` | `900` | 协查链接有效期（签发后固定 15 分钟） |
| `INCIDENT_PUBLIC_BASE_URL` | `http://localhost:8080` | 值班页生成协查链接时使用的公网基址 |

## 已知限制

- 仅支持 OTLP/HTTP **JSON**，不接收 protobuf（gRPC 未实现）；面对 Go/Python 等
  默认 protobuf 的 exporter，需要设置 `OTEL_EXPORTER_OTLP_PROTOCOL=http/json`。
- 以单进程（单 worker）部署为前提：容量计数与判定靠进程内锁 + `BEGIN IMMEDIATE`
  串行化，多 worker 会各自计容量（SQLite 本身仍一致）。
- 两个 Compose 服务各起一个进程、共享一个 SQLite 文件；写操作靠
  `BEGIN IMMEDIATE` 和 WAL 串行化，因此双方都按单 worker 运行。
- 慢根判定基于上报的根 span 自身耗时；若根 span 始终未上报，则只看是否有报错 span。
- 重复 span 按 span_id 去重，保留首次上报的内容。
- 协查链接的「仅一个浏览器可领取」以浏览器 Cookie 为准：同一台机器上的不同浏览器
  算不同领取者；清除 Cookie 后原浏览器会失去查看权（链接本身仍绑定首个领取者）。
- 领取令牌是针对链接与客户端 nonce 的 HMAC；nonce 由浏览器生成并保存在
  `localStorage`，用于响应丢失后的幂等重试，不会随链接泄露给他人。

## 测试

```bash
pip install -r requirements-dev.txt
python -m pytest tests -q      # 32 个用例，注入时钟覆盖窗口/容量/重启与协查场景
```
