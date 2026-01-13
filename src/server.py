"""
Echover central server.

Responsibilities:
- User registration + authentication.
- Store users/groups/memberships in a database.
- Act as a router: A -> Server -> Group members.
- MUST NOT be able to read group message plaintext.

This implementation uses:
- TLS on the transport connection.
- Application-layer E2EE for group messages and key updates.

Run:
  python -m src.server --host 0.0.0.0 --port 8443

The server ensures a self-signed certificate in ./certs/ if none exists.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import socketserver
import sqlite3
import ssl
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .protocol import recv_obj, send_obj

# -----------------------------
# Password hashing
# -----------------------------
import hashlib
import hmac
import secrets


def hash_password(password: str) -> Tuple[bytes, bytes]:
    salt = secrets.token_bytes(16)
    pw_hash = hashlib.sha256(salt + b"|" + password.encode("utf-8")).digest()
    return salt, pw_hash


def verify_password(password: str, salt: bytes, pw_hash: bytes) -> bool:
    cand = hashlib.sha256(salt + b"|" + password.encode("utf-8")).digest()
    return hmac.compare_digest(cand, pw_hash)


# -----------------------------
# TLS certificate generation
# -----------------------------
def ensure_self_signed_cert(cert_dir: Path, hostnames: list[str]) -> Tuple[Path, Path]:
    crt_path = cert_dir / "server.crt"
    key_path = cert_dir / "server.key"
    if crt_path.exists() and key_path.exists():
        return crt_path, key_path

    cert_dir.mkdir(parents=True, exist_ok=True)

    import subprocess
    import tempfile

    names = []
    for h in (hostnames or ["localhost", "127.0.0.1"]):
        h = str(h).strip()
        if not h:
            continue
        if all(ch.isdigit() or ch == "." for ch in h):
            names.append(("IP", h))
        else:
            names.append(("DNS", h))

    if not names:
        names = [("DNS", "localhost"), ("IP", "127.0.0.1")]

    cn = hostnames[0] if hostnames else "localhost"

    alt_lines = []
    dns_i = 1
    ip_i = 1
    for typ, val in names:
        if typ == "DNS":
            alt_lines.append(f"DNS.{dns_i} = {val}")
            dns_i += 1
        else:
            alt_lines.append(f"IP.{ip_i} = {val}")
            ip_i += 1

    cfg = "\n".join(
        [
            "[req]",
            "prompt = no",
            "distinguished_name = dn",
            "x509_extensions = v3_req",
            "",
            "[dn]",
            "C = AT",
            "O = Echover Demo",
            f"CN = {cn}",
            "",
            "[v3_req]",
            "subjectAltName = @alt_names",
            "",
            "[alt_names]",
            *alt_lines,
            "",
        ]
    )

    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(cfg)
        cfg_path = f.name

    try:
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "3650",
                "-keyout",
                str(key_path),
                "-out",
                str(crt_path),
                "-config",
                cfg_path,
                "-extensions",
                "v3_req",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError as e:
        raise RuntimeError(
            "OpenSSL is required to generate the TLS certificate. "
            "Install openssl or create certs/server.crt and certs/server.key manually."
        ) from e
    finally:
        try:
            os.remove(cfg_path)
        except Exception:
            pass

    return crt_path, key_path


# -----------------------------
# Database
# -----------------------------
SCHEMA = r"""
CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY,
  pw_salt  BLOB NOT NULL,
  pw_hash  BLOB NOT NULL,
  pubkey_pem TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS groups (
  group_id TEXT PRIMARY KEY,
  name     TEXT NOT NULL,
  owner    TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS memberships (
  group_id TEXT NOT NULL,
  username TEXT NOT NULL,
  role     TEXT NOT NULL,
  status   TEXT NOT NULL,
  joined_at INTEGER NOT NULL,
  left_at INTEGER,
  PRIMARY KEY (group_id, username),
  FOREIGN KEY (group_id) REFERENCES groups(group_id),
  FOREIGN KEY (username) REFERENCES users(username)
);

CREATE TABLE IF NOT EXISTS pending (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  recipient TEXT NOT NULL,
  payload TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
"""


class EchoverState:
    def __init__(self, db_path: Path):
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.execute("PRAGMA foreign_keys = ON;")
        self.db.executescript(SCHEMA)
        self.db.commit()
        self.db_lock = threading.Lock()

        self.online_lock = threading.Lock()
        self.online: dict[str, "socketserver.BaseRequestHandler"] = {}  # username -> handler instance

    def db_exec(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self.db_lock:
            cur = self.db.execute(sql, params)
            self.db.commit()
            return cur

    def db_query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        self.db.row_factory = sqlite3.Row
        with self.db_lock:
            cur = self.db.execute(sql, params)
            rows = cur.fetchall()
            return rows

    def deliver_or_queue(self, username: str, payload: Dict[str, Any]) -> None:
        """
        If user online: send immediately. Otherwise store in pending as JSON string.
        """
        with self.online_lock:
            handler = self.online.get(username)

        if handler is not None:
            try:
                send_obj(handler.request, payload)
                return
            except Exception:
                # fall back to queue
                pass

        self.db_exec(
            "INSERT INTO pending(recipient, payload, created_at) VALUES (?, ?, ?)",
            (username, json.dumps(payload, separators=(",", ":")), int(time.time())),
        )

    def broadcast_to_group(self, group_id: str, payload: Dict[str, Any], exclude: Optional[str] = None) -> None:
        members = self.db_query(
            "SELECT username FROM memberships WHERE group_id=? AND status='active'",
            (group_id,),
        )
        for r in members:
            u = r["username"]
            if exclude and u == exclude:
                continue
            self.deliver_or_queue(u, payload)


# -----------------------------
# Server
# -----------------------------
class TLSThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, RequestHandlerClass, ssl_context: ssl.SSLContext, state: EchoverState):
        super().__init__(server_address, RequestHandlerClass)
        self.ssl_context = ssl_context
        self.state = state

    def get_request(self):
        sock, addr = super().get_request()
        tls_sock = self.ssl_context.wrap_socket(sock, server_side=True)
        return tls_sock, addr


class EchoverHandler(socketserver.BaseRequestHandler):
    def setup(self):
        self.state: EchoverState = self.server.state
        self.username: Optional[str] = None
        self.req_id_counter = 0

    def _resp(self, req_id: int, ok: bool, data: Any = None, error: str = "") -> None:
        send_obj(
            self.request,
            {"type": "response", "req_id": req_id, "ok": ok, "data": data, "error": error},
        )

    def handle(self):
        try:
            while True:
                msg = recv_obj(self.request)
                if not isinstance(msg, dict):
                    continue
                req_id = int(msg.get("req_id", 0))
                mtype = msg.get("type")
                if mtype == "register":
                    self._handle_register(req_id, msg)
                elif mtype == "login":
                    self._handle_login(req_id, msg)
                else:
                    if not self.username:
                        self._resp(req_id, False, error="Not authenticated")
                        continue
                    if mtype == "create_group":
                        self._handle_create_group(req_id, msg)
                    elif mtype == "join_group":
                        self._handle_join_group(req_id, msg)
                    elif mtype == "leave_group":
                        self._handle_leave_group(req_id, msg)
                    elif mtype == "list_groups":
                        self._handle_list_groups(req_id, msg)
                    elif mtype == "group_members":
                        self._handle_group_members(req_id, msg)
                    elif mtype == "user_pubkey":
                        self._handle_user_pubkey(req_id, msg)
                    elif mtype == "send_group":
                        self._handle_send_group(req_id, msg)
                    elif mtype == "send_direct":
                        self._handle_send_direct(req_id, msg)
                    else:
                        self._resp(req_id, False, error=f"Unknown type: {mtype}")
        except ConnectionError:
            pass
        except ssl.SSLError:
            pass
        except Exception as e:
            import traceback
            traceback.print_exc()
            try:
                self._resp(req_id, False, error=f"Server exception: {type(e).__name__}: {e}")
            except Exception:
                pass

        finally:
            self._cleanup()

    def _cleanup(self):
        if self.username:
            with self.state.online_lock:
                cur = self.state.online.get(self.username)
                if cur is self:
                    del self.state.online[self.username]

    # -----------------------------
    # Handlers
    # -----------------------------
    def _handle_register(self, req_id: int, msg: Dict[str, Any]) -> None:
        username = (msg.get("username") or "").strip()
        password = msg.get("password") or ""
        pubkey_pem = msg.get("pubkey_pem") or ""

        if not username or not password or not pubkey_pem:
            self._resp(req_id, False, error="Missing fields")
            return

        rows = self.state.db_query("SELECT username FROM users WHERE username=?", (username,))
        if rows:
            self._resp(req_id, False, error="Username already exists")
            return

        salt, pw_hash = hash_password(password)
        self.state.db_exec(
            "INSERT INTO users(username, pw_salt, pw_hash, pubkey_pem, created_at) VALUES (?, ?, ?, ?, ?)",
            (username, salt, pw_hash, pubkey_pem, int(time.time())),
        )
        self._resp(req_id, True, data={"username": username})

    def _handle_login(self, req_id: int, msg: Dict[str, Any]) -> None:
        username = (msg.get("username") or "").strip()
        password = msg.get("password") or ""
        if not username or not password:
            self._resp(req_id, False, error="Missing fields")
            return

        rows = self.state.db_query("SELECT pw_salt, pw_hash FROM users WHERE username=?", (username,))
        if not rows:
            self._resp(req_id, False, error="Invalid credentials")
            return

        salt = rows[0]["pw_salt"]
        pw_hash = rows[0]["pw_hash"]
        if not verify_password(password, salt, pw_hash):
            self._resp(req_id, False, error="Invalid credentials")
            return

        self.username = username
        with self.state.online_lock:
            self.state.online[username] = self

        pend = self.state.db_query("SELECT id, payload FROM pending WHERE recipient=? ORDER BY id ASC", (username,))
        for r in pend:
            payload = json.loads(r["payload"])
            try:
                send_obj(self.request, payload)
            except Exception:
                break
        if pend:
            ids = [str(r["id"]) for r in pend]
            self.state.db_exec(f"DELETE FROM pending WHERE id IN ({','.join(['?']*len(ids))})", tuple(ids))

        self._resp(req_id, True, data={"username": username})

    def _handle_create_group(self, req_id: int, msg: Dict[str, Any]) -> None:
        name = (msg.get("name") or "").strip() or "group"
        group_id = str(uuid.uuid4())
        now = int(time.time())
        self.state.db_exec(
            "INSERT INTO groups(group_id, name, owner, created_at) VALUES (?, ?, ?, ?)",
            (group_id, name, self.username, now),
        )
        self.state.db_exec(
            "INSERT INTO memberships(group_id, username, role, status, joined_at, left_at) VALUES (?, ?, ?, 'active', ?, NULL)",
            (group_id, self.username, "owner", now),
        )
        self._resp(req_id, True, data={"group_id": group_id, "name": name, "owner": self.username})

    def _handle_join_group(self, req_id: int, msg: Dict[str, Any]) -> None:
        group_id = (msg.get("group_id") or "").strip()
        if not group_id:
            self._resp(req_id, False, error="Missing group_id")
            return
        g = self.state.db_query("SELECT group_id, owner FROM groups WHERE group_id=?", (group_id,))
        if not g:
            self._resp(req_id, False, error="Group not found")
            return

        now = int(time.time())
        existing = self.state.db_query("SELECT status FROM memberships WHERE group_id=? AND username=?", (group_id, self.username))
        if existing:
            if existing[0]["status"] == "active":
                self._resp(req_id, True, data={"group_id": group_id, "status": "already_member"})
                return
            self.state.db_exec(
                "UPDATE memberships SET status='active', joined_at=?, left_at=NULL WHERE group_id=? AND username=?",
                (now, group_id, self.username),
            )
        else:
            self.state.db_exec(
                "INSERT INTO memberships(group_id, username, role, status, joined_at, left_at) VALUES (?, ?, 'member', 'active', ?, NULL)",
                (group_id, self.username, now),
            )

        ev = {"type": "event", "event": "member_joined", "group_id": group_id, "username": self.username, "ts": now}
        self.state.broadcast_to_group(group_id, ev, exclude=None)

        self._resp(req_id, True, data={"group_id": group_id, "status": "joined", "owner": g[0]["owner"]})

    def _handle_leave_group(self, req_id: int, msg: Dict[str, Any]) -> None:
        group_id = (msg.get("group_id") or "").strip()
        if not group_id:
            self._resp(req_id, False, error="Missing group_id")
            return
        now = int(time.time())

        rows = self.state.db_query(
            "SELECT status, role FROM memberships WHERE group_id=? AND username=?",
            (group_id, self.username),
        )
        if not rows or rows[0]["status"] != "active":
            self._resp(req_id, False, error="Not a member")
            return
        if rows[0]["role"] == "owner":
            self._resp(req_id, False, error="Owner cannot leave (demo limitation). Create a new group instead.")
            return

        self.state.db_exec(
            "UPDATE memberships SET status='inactive', left_at=? WHERE group_id=? AND username=?",
            (now, group_id, self.username),
        )

        ev = {"type": "event", "event": "member_left", "group_id": group_id, "username": self.username, "ts": now}
        self.state.broadcast_to_group(group_id, ev, exclude=None)

        self._resp(req_id, True, data={"group_id": group_id, "status": "left"})

    def _handle_list_groups(self, req_id: int, msg: Dict[str, Any]) -> None:
        rows = self.state.db_query(
            """SELECT g.group_id, g.name, g.owner, m.role
               FROM groups g
               JOIN memberships m ON g.group_id=m.group_id
               WHERE m.username=? AND m.status='active'
               ORDER BY g.created_at ASC""",
            (self.username,),
        )
        groups = [{"group_id": r["group_id"], "name": r["name"], "owner": r["owner"], "role": r["role"]} for r in rows]
        self._resp(req_id, True, data={"groups": groups})

    def _handle_group_members(self, req_id: int, msg: Dict[str, Any]) -> None:
        group_id = (msg.get("group_id") or "").strip()
        rows = self.state.db_query(
            "SELECT username, role FROM memberships WHERE group_id=? AND status='active' ORDER BY role DESC, username ASC",
            (group_id,),
        )
        members = [{"username": r["username"], "role": r["role"]} for r in rows]
        self._resp(req_id, True, data={"group_id": group_id, "members": members})

    def _handle_user_pubkey(self, req_id: int, msg: Dict[str, Any]) -> None:
        username = (msg.get("username") or "").strip()
        rows = self.state.db_query("SELECT pubkey_pem FROM users WHERE username=?", (username,))
        if not rows:
            self._resp(req_id, False, error="User not found")
            return
        self._resp(req_id, True, data={"username": username, "pubkey_pem": rows[0]["pubkey_pem"]})

    def _require_active_member(self, group_id: str) -> bool:
        rows = self.state.db_query(
            "SELECT status FROM memberships WHERE group_id=? AND username=?",
            (group_id, self.username),
        )
        return bool(rows) and rows[0]["status"] == "active"

    def _handle_send_group(self, req_id: int, msg: Dict[str, Any]) -> None:
        group_id = (msg.get("group_id") or "").strip()
        if not group_id:
            self._resp(req_id, False, error="Missing group_id")
            return
        if not self._require_active_member(group_id):
            self._resp(req_id, False, error="Not a group member")
            return

        envelope = msg.get("envelope")
        if not isinstance(envelope, dict):
            self._resp(req_id, False, error="Missing envelope")
            return

        payload = {
            "type": "group_msg",
            "group_id": group_id,
            "from": self.username,
            "envelope": envelope,
            "ts": int(time.time()),
        }
        self.state.broadcast_to_group(group_id, payload, exclude=self.username)
        self._resp(req_id, True, data={"delivered_to_group": group_id})

    def _handle_send_direct(self, req_id: int, msg: Dict[str, Any]) -> None:
        to = (msg.get("to") or "").strip()
        payload = msg.get("payload")
        if not to or not isinstance(payload, dict):
            self._resp(req_id, False, error="Missing fields")
            return
        out = {"type": "direct_msg", "from": self.username, "to": to, "payload": payload, "ts": int(time.time())}
        self.state.deliver_or_queue(to, out)
        self._resp(req_id, True, data={"delivered_to": to})


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--db", default="echover.db")
    ap.add_argument("--cert-dir", default="certs")
    args = ap.parse_args()

    base_dir = Path(__file__).resolve().parents[1]  # project root (../)
    cert_dir = (base_dir / args.cert_dir).resolve()
    crt, key = ensure_self_signed_cert(cert_dir, hostnames=["localhost", "127.0.0.1", args.host])

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(crt), keyfile=str(key))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    state = EchoverState((base_dir / args.db).resolve())

    with TLSThreadingTCPServer((args.host, args.port), EchoverHandler, ctx, state) as srv:
        print(f"[server] Echover listening on {args.host}:{args.port} (TLS).")
        print(f"[server] DB: {state.db}")
        print(f"[server] Cert: {crt}")
        srv.serve_forever()


if __name__ == "__main__":
    main()
