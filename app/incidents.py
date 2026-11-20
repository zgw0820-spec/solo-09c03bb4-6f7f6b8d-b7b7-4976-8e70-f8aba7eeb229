"""Investigation links ("协查链接") bound to one service in one trace.

Semantics implemented here (all persisted in the collector's SQLite file, so
they survive restarts):

* A duty operator creates a link from a *retained* trace detail.  The link is
  bound to exactly one service name.  It is valid for ``ttl_seconds`` counted
  from issuance and that expiry never moves.
* Opening the link shows a claim page.  Exactly one browser can claim it: the
  claim is a conditional ``UPDATE ... WHERE claimed_at IS NULL`` inside a
  ``BEGIN IMMEDIATE`` transaction, so concurrent claims have exactly one
  winner.
* Claiming is idempotent for the winner.  The token is derived with an HMAC
  key that lives in the database, so a retry with the same client nonce after
  a lost response re-derives the same token instead of failing.  No raw token
  is stored, only its hash.
* The token only ever grants the selected service's span name, duration and
  status -- never the raw OTLP body and never another service's spans.
* Revocation and expiry are re-checked on every read, so an already-claimed
  browser cannot fetch again after either event.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .config import Settings

DEFAULT_TTL_SECONDS = 15 * 60

INCIDENT_SCHEMA = """
CREATE TABLE IF NOT EXISTS incident_links (
    link_id TEXT PRIMARY KEY,
    trace_id TEXT NOT NULL,
    service TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    revoked_at REAL,
    claimed_at REAL,
    claim_secret_hash TEXT,
    claim_nonce TEXT
);

CREATE INDEX IF NOT EXISTS idx_incident_links_expiry
    ON incident_links (expires_at);

CREATE TABLE IF NOT EXISTS incident_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class LinkError(Exception):
    """An investigation link operation was refused."""

    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class ClaimResult:
    link_id: str
    token: str
    claimed_at: float
    already_claimed: bool


def _hash_secret(link_id: str, nonce: str, secret: str) -> str:
    return hashlib.sha256(f"{link_id}:{nonce}:{secret}".encode("utf-8")).hexdigest()


def _derive_secret(signing_key: str, link_id: str, nonce: str) -> str:
    """Deterministically derive the claim token from the client nonce.

    This is what makes "claim succeeded but the response was lost" recoverable:
    a retry carrying the same nonce gets the same token, and the stored hash
    proves it is the same claimant.  Without the DB-held signing key the token
    cannot be computed from the nonce alone.
    """
    return hmac.new(
        f"incident-claim:{signing_key}:{link_id}".encode("utf-8"),
        nonce.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


class IncidentStore:
    """Persistence for investigation links, sharing the collector's DB file."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._lock = threading.RLock()
        self._path = Path(settings.db_path)
        if str(self._path) != ":memory:":
            self._path.parent.mkdir(parents=True, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._path), timeout=30.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def init_schema(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.executescript(INCIDENT_SCHEMA)
            finally:
                conn.close()

    @contextmanager
    def _tx(self, conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        else:
            conn.execute("COMMIT")

    def _signing_key(self, conn: sqlite3.Connection) -> str:
        row = conn.execute(
            "SELECT value FROM incident_meta WHERE key = 'claim_signing_key'"
        ).fetchone()
        if row is not None:
            return row["value"]
        conn.execute(
            "INSERT OR IGNORE INTO incident_meta (key, value) VALUES ('claim_signing_key', ?)",
            (secrets.token_hex(32),),
        )
        row = conn.execute(
            "SELECT value FROM incident_meta WHERE key = 'claim_signing_key'"
        ).fetchone()
        assert row is not None
        return row["value"]

    # -- creating -----------------------------------------------------------

    def create_link(
        self,
        trace_id: str,
        service: str,
        now: float,
        ttl_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Issue a link for ``service``; expiry is fixed at ``now + ttl``."""
        ttl = (
            self.settings.incident_ttl_seconds
            if ttl_seconds is None
            else float(ttl_seconds)
        )
        if ttl <= 0:
            raise LinkError("ttl must be > 0")
        link_id = secrets.token_urlsafe(24)
        expires_at = now + ttl
        with self._lock:
            conn = self._connect()
            try:
                with self._tx(conn):
                    conn.execute(
                        "INSERT INTO incident_links "
                        "(link_id, trace_id, service, created_at, expires_at) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (link_id, trace_id, service, now, expires_at),
                    )
            finally:
                conn.close()
        return {
            "link_id": link_id,
            "trace_id": trace_id,
            "service": service,
            "created_at": now,
            "expires_at": expires_at,
            "ttl_seconds": ttl,
        }

    # -- reading state ------------------------------------------------------

    def _row(self, conn: sqlite3.Connection, link_id: str) -> sqlite3.Row | None:
        return conn.execute(
            "SELECT * FROM incident_links WHERE link_id = ?", (link_id,)
        ).fetchone()

    @staticmethod
    def _status(row: sqlite3.Row, now: float) -> str:
        if row["revoked_at"] is not None:
            return "revoked"
        if now >= row["expires_at"]:
            return "expired"
        if row["claimed_at"] is not None:
            return "claimed"
        return "open"

    def describe(self, link_id: str, now: float) -> dict[str, Any] | None:
        """Public, non-secret description used by the claim page."""
        with self._lock:
            conn = self._connect()
            try:
                row = self._row(conn, link_id)
            finally:
                conn.close()
        if row is None:
            return None
        status = self._status(row, now)
        return {
            "link_id": row["link_id"],
            "trace_id": row["trace_id"],
            "service": row["service"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "claimed_at": row["claimed_at"],
            "revoked_at": row["revoked_at"],
            "status": status,
            "can_claim": status == "open",
        }

    def list_links(self, trace_id: str, now: float) -> list[dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT link_id FROM incident_links WHERE trace_id = ? "
                    "ORDER BY created_at DESC, link_id",
                    (trace_id,),
                ).fetchall()
            finally:
                conn.close()
        described = [self.describe(row["link_id"], now) for row in rows]
        return [item for item in described if item is not None]

    # -- claiming -----------------------------------------------------------

    def claim(self, link_id: str, nonce: str, now: float) -> ClaimResult:
        """Claim a link exactly once; same-nonce retries are idempotent."""
        if not nonce or len(nonce) > 200:
            raise LinkError("claim nonce is required")
        with self._lock:
            conn = self._connect()
            try:
                with self._tx(conn):
                    row = self._row(conn, link_id)
                    if row is None:
                        raise LinkError("link not found", 404)
                    if row["revoked_at"] is not None:
                        raise LinkError("link was revoked", 410)
                    if now >= row["expires_at"]:
                        raise LinkError("link has expired", 410)

                    signing_key = self._signing_key(conn)
                    token = _derive_secret(signing_key, link_id, nonce)

                    if row["claimed_at"] is not None:
                        stored_hash = row["claim_secret_hash"] or ""
                        if (
                            row["claim_nonce"] == nonce
                            and hmac.compare_digest(
                                stored_hash, _hash_secret(link_id, nonce, token)
                            )
                        ):
                            return ClaimResult(
                                link_id=link_id,
                                token=token,
                                claimed_at=row["claimed_at"],
                                already_claimed=True,
                            )
                        raise LinkError("link was already claimed", 409)

                    updated = conn.execute(
                        "UPDATE incident_links "
                        "SET claimed_at = ?, claim_nonce = ?, claim_secret_hash = ? "
                        "WHERE link_id = ? AND claimed_at IS NULL",
                        (
                            now,
                            nonce,
                            _hash_secret(link_id, nonce, token),
                            link_id,
                        ),
                    ).rowcount
                    if not updated:  # pragma: no cover - BEGIN IMMEDIATE serialises us
                        raise LinkError("link was already claimed", 409)
                    return ClaimResult(
                        link_id=link_id,
                        token=token,
                        claimed_at=now,
                        already_claimed=False,
                    )
            finally:
                conn.close()

    def verify_token(self, link_id: str, token: str, now: float) -> None:
        """Raise :class:`LinkError` unless the token belongs to a live claim."""
        if not token:
            raise LinkError("claim token required", 401)
        with self._lock:
            conn = self._connect()
            try:
                row = self._row(conn, link_id)
            finally:
                conn.close()
        if row is None:
            raise LinkError("link not found", 404)
        if row["revoked_at"] is not None:
            raise LinkError("link was revoked", 410)
        if now >= row["expires_at"]:
            raise LinkError("link has expired", 410)
        if row["claimed_at"] is None:
            raise LinkError("link has not been claimed", 403)
        expected = row["claim_secret_hash"] or ""
        actual = _hash_secret(link_id, row["claim_nonce"] or "", token)
        if not hmac.compare_digest(expected, actual):
            raise LinkError("invalid claim token", 403)

    # -- operator controls --------------------------------------------------

    def revoke(self, link_id: str, now: float) -> dict[str, Any]:
        with self._lock:
            conn = self._connect()
            try:
                with self._tx(conn):
                    row = self._row(conn, link_id)
                    if row is None:
                        raise LinkError("link not found", 404)
                    if row["revoked_at"] is None:
                        conn.execute(
                            "UPDATE incident_links SET revoked_at = ? WHERE link_id = ?",
                            (now, link_id),
                        )
            finally:
                conn.close()
        described = self.describe(link_id, now)
        assert described is not None
        return described
