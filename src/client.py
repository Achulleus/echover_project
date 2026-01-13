"""
Echover client.

Implements:
- Register/login to server (TLS).
- Create/join/leave group.
- End-to-end encrypted group chat with per-group shared key using
  AES-CTR + HMAC-SHA256 in Encrypt-then-MAC composition.
- Membership-change rekeying when users join/leave.

Run:
  python -m src.client --host 127.0.0.1 --port 8443

Commands (after login):
  groups
  create <group_name>
  join <group_id>
  leave <group_id>
  members <group_id>
  send <group_id> <message...>
  help
  exit

Notes:
- Private keys are stored in ./keys/<username>_private.json (AES-CTR + HMAC, key derived from password).
- Group keys are stored in ./keys/<username>_groupkeys.json.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import queue
import socket
import ssl
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .protocol import recv_obj, send_obj
from . import crypto


# -----------------------------
# Local storage
# -----------------------------
class LocalStore:
    def __init__(self, base_dir: Path, username: str):
        self.base_dir = base_dir
        self.username = username
        self.keys_dir = base_dir / "keys"
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.priv_path = self.keys_dir / f"{username}_private.json"
        self.pub_path = self.keys_dir / f"{username}_public.pem"
        self.groupkeys_path = self.keys_dir / f"{username}_groupkeys.json"

    def save_private_key_wrapped(self, wrapped_json: dict) -> None:
        tmp = self.priv_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(wrapped_json, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.priv_path)

    def save_private_key(self, der: bytes, password: str) -> None:
        wrapped = crypto.wrap_blob_with_password(password, der, aad=b"ECHO-PRIVKEY")
        self.save_private_key_wrapped(wrapped)

    def save_public_key(self, pem: bytes) -> None:
        self.pub_path.write_bytes(pem)

    def load_private_key(self, password: str):
        wrapped = json.loads(self.priv_path.read_text(encoding="utf-8"))
        der = crypto.unwrap_blob_with_password(password, wrapped)
        return crypto.import_private_key_der(der)

    def load_groupkeys(self) -> Dict[str, Any]:
        if not self.groupkeys_path.exists():
            return {"groups": {}}
        return json.loads(self.groupkeys_path.read_text(encoding="utf-8"))

    def save_groupkeys(self, data: Dict[str, Any]) -> None:
        tmp = self.groupkeys_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.groupkeys_path)

    def set_group_key(self, group_id: str, epoch: int, key: bytes) -> None:
        data = self.load_groupkeys()
        g = data.setdefault("groups", {}).setdefault(group_id, {"current_epoch": 0, "keys": {}, "send": {}})
        g.setdefault("send", {})
        g["keys"][str(epoch)] = crypto.b64e(key)
        if epoch > int(g.get("current_epoch", 0)):
            g["current_epoch"] = epoch
        self.save_groupkeys(data)

    def _ensure_send_state(self, data: Dict[str, Any], group_id: str, epoch: int) -> Tuple[bytes, int]:
        g = data.setdefault("groups", {}).setdefault(group_id, {"current_epoch": 0, "keys": {}, "send": {}})
        send = g.setdefault("send", {})
        st = send.get(str(epoch))
        if not isinstance(st, dict):
            st = None
        if not st:
            # per-epoch per-sender nonce prefix + monotone counter ensures CTR IV uniqueness
            st = {"nonce": crypto.b64e(crypto.random_bytes(8)), "ctr": 1}
            send[str(epoch)] = st
        nonce = crypto.b64d(st["nonce"])
        ctr = int(st.get("ctr", 1))
        return nonce, ctr

    def next_send_params(self, group_id: str, epoch: int) -> crypto.CtrParams:
        data = self.load_groupkeys()
        nonce, ctr = self._ensure_send_state(data, group_id, epoch)

        g = data["groups"][group_id]
        g["send"][str(epoch)]["ctr"] = int(ctr) + 1
        self.save_groupkeys(data)
        return crypto.CtrParams(nonce_prefix=nonce, counter=int(ctr))

    def get_group_key(self, group_id: str, epoch: int) -> Optional[bytes]:
        data = self.load_groupkeys()
        g = data.get("groups", {}).get(group_id)
        if not g:
            return None
        b64 = g.get("keys", {}).get(str(epoch))
        if not b64:
            return None
        return crypto.b64d(b64)

    def get_current_epoch(self, group_id: str) -> int:
        data = self.load_groupkeys()
        g = data.get("groups", {}).get(group_id)
        if not g:
            return 0
        return int(g.get("current_epoch", 0))


# -----------------------------
# Connection
# -----------------------------
class ServerConnection:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self._req_lock = threading.Lock()
        self._next_req_id = 1
        self._resp_queues: dict[int, "queue.Queue[dict]"] = {}
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._recv_loop, daemon=True)

        self.on_event = lambda msg: None
        self.on_group_msg = lambda msg: None
        self.on_direct_msg = lambda msg: None

    def start(self):
        self._thread.start()

    def close(self):
        self._stop.set()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass

    def request(self, mtype: str, **fields) -> dict:
        with self._req_lock:
            req_id = self._next_req_id
            self._next_req_id += 1
            q: "queue.Queue[dict]" = queue.Queue(maxsize=1)
            self._resp_queues[req_id] = q
            send_obj(self.sock, {"type": mtype, "req_id": req_id, **fields})

        try:
            try:
                resp = q.get(timeout=15)
            except queue.Empty as e:
                raise TimeoutError(
                    "Request timed out (15s). The server did not answer. "
                    "Check the server console for an exception."
                ) from e
        finally:
            with self._req_lock:
                self._resp_queues.pop(req_id, None)
        return resp

    def send(self, mtype: str, **fields) -> None:
        with self._req_lock:
            req_id = self._next_req_id
            self._next_req_id += 1
        send_obj(self.sock, {"type": mtype, "req_id": req_id, **fields})

    def _recv_loop(self):
        try:
            while not self._stop.is_set():
                try:
                    msg = recv_obj(self.sock)
                except TimeoutError:
                    continue
                except OSError as e:
                    self._stop.set()
                    break

                mtype = msg.get("type")
                if mtype == "response":
                    req_id = int(msg.get("req_id", 0))
                    q = self._resp_queues.get(req_id)
                    if q:
                        q.put(msg)
                elif mtype == "event":
                    threading.Thread(target=self.on_event, args=(msg,), daemon=True).start()
                elif mtype == "group_msg":
                    threading.Thread(target=self.on_group_msg, args=(msg,), daemon=True).start()
                elif mtype == "direct_msg":
                    threading.Thread(target=self.on_direct_msg, args=(msg,), daemon=True).start()
                else:
                    threading.Thread(target=self.on_event, args=(msg,), daemon=True).start()
        except Exception as e:
            self._stop.set()
            try:
                import traceback

                print("[!] Receiver thread crashed:")
                traceback.print_exc()
            except Exception:
                pass


# -----------------------------
# Client app
# -----------------------------
@dataclass
class GroupInfo:
    group_id: str
    name: str
    owner: str
    role: str  # "owner" | "member"


class EchoverClient:
    def __init__(self, host: str, port: int, cafile: Path):
        self.host = host
        self.port = port
        self.cafile = cafile

        self.base_dir = Path(__file__).resolve().parents[1]
        self.conn: Optional[ServerConnection] = None

        self.username: Optional[str] = None
        self.store: Optional[LocalStore] = None
        self.privkey = None  # RSA private key
        self.pubkey_pem: Optional[bytes] = None

        self.groups: dict[str, GroupInfo] = {}
        self.pubkey_cache: dict[str, bytes] = {}  # username -> pem

    def _connect(self) -> ServerConnection:
        raw = socket.create_connection((self.host, self.port), timeout=10)
        raw.settimeout(None)
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(self.cafile))
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        tls = ctx.wrap_socket(raw, server_hostname=self.host)
        tls.settimeout(None)
        return ServerConnection(tls)

    def _get_user_pubkey(self, username: str) -> bytes:
        if username in self.pubkey_cache:
            return self.pubkey_cache[username]
        assert self.conn is not None
        resp = self.conn.request("user_pubkey", username=username)
        if not resp.get("ok"):
            raise RuntimeError(resp.get("error", "user_pubkey failed"))
        pem = resp["data"]["pubkey_pem"].encode("utf-8")
        self.pubkey_cache[username] = pem
        return pem

    def _refresh_groups(self) -> None:
        assert self.conn is not None
        resp = self.conn.request("list_groups")
        if not resp.get("ok"):
            raise RuntimeError(resp.get("error", "list_groups failed"))
        self.groups.clear()
        for g in resp["data"]["groups"]:
            gi = GroupInfo(**g)
            self.groups[gi.group_id] = gi

    def _ensure_group_key(self, group_id: str) -> None:
        assert self.store is not None
        if self.store.get_current_epoch(group_id) == 0:
            self.store.set_group_key(group_id, 1, crypto.random_group_key())

    def _rotate_group_key_and_distribute(self, group_id: str) -> None:
        assert self.username is not None
        assert self.conn is not None
        assert self.store is not None
        assert self.privkey is not None

        gi = self.groups.get(group_id)
        if not gi or gi.role != "owner":
            return

        cur_epoch = self.store.get_current_epoch(group_id)
        if cur_epoch == 0:
            self._ensure_group_key(group_id)
            cur_epoch = 1

        new_epoch = cur_epoch + 1
        new_key = crypto.random_group_key()
        self.store.set_group_key(group_id, new_epoch, new_key)

        resp = self.conn.request("group_members", group_id=group_id)
        if not resp.get("ok"):
            print(f"[!] Cannot fetch members for rekey: {resp.get('error')}")
            return
        members = [m["username"] for m in resp["data"]["members"]]

        for member in members:
            if member == self.username:
                continue
            try:
                member_pub = self._get_user_pubkey(member)
                enc_key = crypto.rsa_encrypt(member_pub, new_key)
                sig_data = crypto.key_update_sig_data(group_id, new_epoch, enc_key)
                sig = crypto.rsa_sign(self.privkey, sig_data)

                payload = {
                    "kind": "group_key_update",
                    "group_id": group_id,
                    "epoch": new_epoch,
                    "enc_key": crypto.b64e(enc_key),
                    "signer": self.username,
                    "sig": crypto.b64e(sig),
                }
                self.conn.request("send_direct", to=member, payload=payload)
            except Exception as e:
                print(f"[!] Rekey to {member} failed: {e}")

        print(f"[*] Rekeyed group {group_id} -> epoch {new_epoch} (distributed to {len(members)-1} members)")

    def _handle_event(self, msg: Dict[str, Any]) -> None:
        ev = msg.get("event")
        group_id = msg.get("group_id")
        u = msg.get("username")
        if ev == "member_joined":
            print(f"[event] {u} joined group {group_id}")
            if group_id in self.groups and self.groups[group_id].role == "owner":
                self._rotate_group_key_and_distribute(group_id)
        elif ev == "member_left":
            print(f"[event] {u} left group {group_id}")
            if group_id in self.groups and self.groups[group_id].role == "owner":
                self._rotate_group_key_and_distribute(group_id)
        else:
            print(f"[event] {msg}")

    def _handle_direct(self, msg: Dict[str, Any]) -> None:
        payload = msg.get("payload", {})
        if not isinstance(payload, dict):
            return
        kind = payload.get("kind")
        if kind == "group_key_update":
            self._handle_group_key_update(msg)
        elif kind == "key_request":
            self._handle_key_request(msg)
        else:
            print(f"[direct] from {msg.get('from')}: {payload}")

    def _handle_key_request(self, msg: Dict[str, Any]) -> None:
        assert self.username is not None and self.conn is not None and self.store is not None and self.privkey is not None
        from_user = msg.get("from")
        payload = msg.get("payload", {})
        group_id = payload.get("group_id")
        if not from_user or not group_id:
            return

        # Only the group owner may answer key requests.
        gi = self.groups.get(group_id)
        if not gi or gi.role != "owner":
            return

        try:
            resp = self.conn.request("group_members", group_id=group_id)
            if not resp.get("ok"):
                return
            active = {m["username"] for m in resp["data"]["members"]}
        except Exception:
            return

        if from_user not in active:
            print(f"[*] Ignoring key request from non-member {from_user} for group {group_id}")
            return

        epoch = self.store.get_current_epoch(group_id)
        key = self.store.get_group_key(group_id, epoch)
        if not key:
            return

        try:
            member_pub = self._get_user_pubkey(from_user)
            enc_key = crypto.rsa_encrypt(member_pub, key)
            sig_data = crypto.key_update_sig_data(group_id, epoch, enc_key)
            sig = crypto.rsa_sign(self.privkey, sig_data)
            out = {
                "kind": "group_key_update",
                "group_id": group_id,
                "epoch": epoch,
                "enc_key": crypto.b64e(enc_key),
                "signer": self.username,
                "sig": crypto.b64e(sig),
            }
            self.conn.request("send_direct", to=from_user, payload=out)
            print(f"[*] Sent key epoch {epoch} for group {group_id} to {from_user}")
        except Exception as e:
            print(f"[!] Failed to answer key request: {e}")

    def _handle_group_key_update(self, msg: Dict[str, Any]) -> None:
        assert self.store is not None and self.privkey is not None
        payload = msg["payload"]
        group_id = payload.get("group_id")
        epoch = int(payload.get("epoch", 0))
        signer = payload.get("signer")
        enc_key_b64 = payload.get("enc_key")
        sig_b64 = payload.get("sig")
        if not group_id or not epoch or not signer or not enc_key_b64 or not sig_b64:
            return

        gi = self.groups.get(group_id)
        if gi and signer != gi.owner:
            print(f"[!] Ignoring key update: signer {signer} is not owner {gi.owner}")
            return

        enc_key = crypto.b64d(enc_key_b64)
        sig = crypto.b64d(sig_b64)

        try:
            signer_pub = self._get_user_pubkey(signer)
            sig_data = crypto.key_update_sig_data(group_id, epoch, enc_key)
            if not crypto.rsa_verify(signer_pub, sig, sig_data):
                print("[!] Invalid key update signature; ignoring.")
                return
            key = crypto.rsa_decrypt(self.privkey, enc_key, out_len=32)
            if len(key) != 32:
                print("[!] Invalid group key length; ignoring.")
                return
            self.store.set_group_key(group_id, epoch, key)
            print(f"[*] Stored group key for {group_id} epoch {epoch} (from {signer})")
        except Exception as e:
            print(f"[!] Failed processing key update: {e}")

    def _handle_group_msg(self, msg: Dict[str, Any]) -> None:
        assert self.store is not None
        group_id = msg.get("group_id")
        envelope = msg.get("envelope", {})
        sender = msg.get("from")
        if not group_id or not isinstance(envelope, dict) or not sender:
            return

        epoch = int(envelope.get("epoch", 0))
        nonce_b64 = envelope.get("nonce")
        ctr = envelope.get("ctr")
        ct_b64 = envelope.get("ciphertext")
        tag_b64 = envelope.get("tag")
        sig_b64 = envelope.get("sig")
        if not epoch or not nonce_b64 or ctr is None or not ct_b64 or not tag_b64 or not sig_b64:
            return

        key = self.store.get_group_key(group_id, epoch)
        if key is None:
            gi = self.groups.get(group_id)
            if gi and self.conn:
                self.conn.request("send_direct", to=gi.owner, payload={"kind": "key_request", "group_id": group_id, "epoch": epoch})
            print(f"[group {group_id}] (cannot decrypt epoch {epoch}) from {sender}: <missing key>")
            return

        nonce = crypto.b64d(nonce_b64)
        ct = crypto.b64d(ct_b64)
        tag = crypto.b64d(tag_b64)
        sig = crypto.b64d(sig_b64)
        params = crypto.CtrParams(nonce_prefix=nonce, counter=int(ctr))

        try:
            sender_pub = self._get_user_pubkey(sender)
            sig_data = crypto.group_msg_sig_data(group_id, epoch, sender, params, ct, tag)
            if not crypto.rsa_verify(sender_pub, sig, sig_data):
                print(f"[!] Invalid message signature from {sender}; ignoring.")
                return

            pt = crypto.etm_decrypt(key, group_id, epoch, sender, params, ct, tag)
            body = json.loads(pt.decode("utf-8"))
            ts = body.get("ts")
            text = body.get("text")
            tstr = time.strftime("%H:%M:%S", time.localtime(ts or time.time()))
            print(f"[{tstr}] {group_id} {sender}: {text}")
        except Exception as e:
            print(f"[!] Failed decrypting group message: {e}")

    def register(self, username: str, password: str) -> None:
        self.store = LocalStore(self.base_dir, username)
        if self.store.priv_path.exists():
            raise RuntimeError("Private key already exists locally for this username (delete ./keys/ to re-register)")

        # Generate RSA keypair (RSA-2048).
        priv = crypto.generate_rsa_private_key()
        der = crypto.export_private_key_der(priv)
        pub_pem = crypto.serialize_public_key_pem(priv)

        self.store.save_private_key(der, password=password)
        self.store.save_public_key(pub_pem)

        conn = self._connect()
        conn.start()
        resp = conn.request("register", username=username, password=password, pubkey_pem=pub_pem.decode("utf-8"))
        conn.close()
        if not resp.get("ok"):
            raise RuntimeError(resp.get("error", "register failed"))
        print(f"[*] Registered {username}. Keys saved to {self.store.keys_dir}")

    def login(self, username: str, password: str) -> None:
        self.username = username
        self.store = LocalStore(self.base_dir, username)
        if not self.store.priv_path.exists():
            raise RuntimeError("No local private key found. Register first (same working directory).")

        self.privkey = self.store.load_private_key(password=password)
        self.pubkey_pem = self.store.pub_path.read_bytes() if self.store.pub_path.exists() else None

        self.conn = self._connect()
        self.conn.on_event = self._handle_event
        self.conn.on_group_msg = self._handle_group_msg
        self.conn.on_direct_msg = self._handle_direct
        self.conn.start()

        resp = self.conn.request("login", username=username, password=password)
        if not resp.get("ok"):
            self.conn.close()
            self.conn = None
            raise RuntimeError(resp.get("error", "login failed"))

        self._refresh_groups()
        print(f"[*] Logged in as {username}.")

    def create_group(self, name: str) -> None:
        assert self.conn is not None
        resp = self.conn.request("create_group", name=name)
        if not resp.get("ok"):
            print(f"[!] create_group failed: {resp.get('error')}")
            return
        g = resp["data"]
        gi = GroupInfo(group_id=g["group_id"], name=g["name"], owner=g["owner"], role="owner")
        self.groups[gi.group_id] = gi

        assert self.store is not None
        self._ensure_group_key(gi.group_id)

        print(f"[*] Created group '{gi.name}' id={gi.group_id}. You are the owner.")
        print("[*] When members join/leave, your client will automatically rotate and distribute the group key (epoch).")

    def join_group(self, group_id: str) -> None:
        assert self.conn is not None
        resp = self.conn.request("join_group", group_id=group_id)
        if not resp.get("ok"):
            print(f"[!] join failed: {resp.get('error')}")
            return
        self._refresh_groups()
        gi = self.groups.get(group_id)
        if gi:
            print(f"[*] Joined group {group_id}. Owner: {gi.owner}. Waiting for key update...")
        else:
            print(f"[*] Joined group {group_id}. (Not in list yet; try 'groups')")

    def leave_group(self, group_id: str) -> None:
        assert self.conn is not None
        resp = self.conn.request("leave_group", group_id=group_id)
        if not resp.get("ok"):
            print(f"[!] leave failed: {resp.get('error')}")
            return
        self._refresh_groups()
        print(f"[*] Left group {group_id}.")

    def list_groups(self) -> None:
        self._refresh_groups()
        if not self.groups:
            print("(no groups)")
            return
        for g in self.groups.values():
            print(f"- {g.group_id}  name={g.name}  owner={g.owner}  role={g.role}")

    def members(self, group_id: str) -> None:
        assert self.conn is not None
        resp = self.conn.request("group_members", group_id=group_id)
        if not resp.get("ok"):
            print(f"[!] members failed: {resp.get('error')}")
            return
        for m in resp["data"]["members"]:
            print(f"- {m['username']} ({m['role']})")

    def send_group(self, group_id: str, text: str) -> None:
        assert self.conn is not None and self.username is not None and self.store is not None and self.privkey is not None

        gi = self.groups.get(group_id)
        if not gi:
            print("[!] Unknown group. Use 'groups' first.")
            return

        epoch = self.store.get_current_epoch(group_id)
        key = self.store.get_group_key(group_id, epoch) if epoch else None
        if not key:
            print("[!] No group key yet. Wait for owner to send key update.")
            self.conn.request("send_direct", to=gi.owner, payload={"kind": "key_request", "group_id": group_id, "epoch": 0})
            return

        body = {"ts": int(time.time()), "text": text}
        plaintext = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        params = self.store.next_send_params(group_id, epoch)
        ct, tag = crypto.etm_encrypt(key, group_id, epoch, self.username, params, plaintext)

        sig_data = crypto.group_msg_sig_data(group_id, epoch, self.username, params, ct, tag)
        sig = crypto.rsa_sign(self.privkey, sig_data)

        envelope = {
            "epoch": epoch,
            "nonce": crypto.b64e(params.nonce_prefix),
            "ctr": params.counter,
            "ciphertext": crypto.b64e(ct),
            "tag": crypto.b64e(tag),
            "sig": crypto.b64e(sig),
        }

        resp = self.conn.request("send_group", group_id=group_id, envelope=envelope)
        if not resp.get("ok"):
            print(f"[!] send failed: {resp.get('error')}")


def repl(client: EchoverClient):
    print("Type 'help' for commands.")
    while True:
        try:
            line = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        parts = line.split()
        cmd = parts[0].lower()

        if cmd in ("exit", "quit"):
            break
        if cmd == "help":
            print("Commands:")
            print("  groups")
            print("  create <group_name>")
            print("  join <group_id>")
            print("  leave <group_id>")
            print("  members <group_id>")
            print("  send <group_id> <message...>")
            print("  exit")
            continue

        try:
            if cmd == "groups":
                client.list_groups()
            elif cmd == "create":
                name = " ".join(parts[1:]) if len(parts) > 1 else "group"
                client.create_group(name)
            elif cmd == "join":
                client.join_group(parts[1])
            elif cmd == "leave":
                client.leave_group(parts[1])
            elif cmd == "members":
                client.members(parts[1])
            elif cmd == "send":
                if len(parts) < 3:
                    print("Usage: send <group_id> <message...>")
                    continue
                gid = parts[1]
                msg = " ".join(parts[2:])
                client.send_group(gid, msg)
            else:
                print("Unknown command. Type 'help'.")
        except Exception as e:
            msg = str(e)
            if msg:
                print(f"[!] {type(e).__name__}: {msg}")
            else:
                print(f"[!] {type(e).__name__}: {repr(e)}")

    if client.conn:
        client.conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--cafile", default="certs/server.crt", help="CA/cert to trust (server self-signed cert).")
    ap.add_argument("--register", action="store_true", help="Run registration flow then exit.")
    ap.add_argument("--username", default="")
    args = ap.parse_args()

    base_dir = Path(__file__).resolve().parents[1]
    cafile = (base_dir / args.cafile).resolve()
    if not cafile.exists():
        print(f"[!] CA file not found: {cafile}")
        print("    Start the server once so it generates ./certs/server.crt, then retry.")
        sys.exit(1)

    client = EchoverClient(args.host, args.port, cafile=cafile)

    if args.register:
        username = args.username or input("Choose username: ").strip()
        pw = getpass.getpass("Choose password: ")
        pw2 = getpass.getpass("Repeat password: ")
        if pw != pw2:
            print("[!] Passwords do not match.")
            return
        client.register(username, pw)
        return

    username = args.username or input("Username: ").strip()
    pw = getpass.getpass("Password: ")
    client.login(username, pw)
    repl(client)


if __name__ == "__main__":
    main()
