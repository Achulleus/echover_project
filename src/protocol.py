"""
Echover - minimal framing and JSON helpers.

All application messages are JSON objects encoded as UTF-8, framed with a 4-byte
big-endian length prefix.

This framing works over plain TCP or TLS sockets.
"""
from __future__ import annotations

import json
import socket
from typing import Any, Dict, Optional


MAX_FRAME = 10 * 1024 * 1024  # 10MB safety cap


def _recvall(sock: socket.socket, n: int) -> bytes:
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Socket closed while receiving data")
        data.extend(chunk)
    return bytes(data)


def send_obj(sock: socket.socket, obj: Dict[str, Any]) -> None:
    raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(raw) > MAX_FRAME:
        raise ValueError(f"Frame too large ({len(raw)} bytes)")
    header = len(raw).to_bytes(4, "big")
    sock.sendall(header + raw)


def recv_obj(sock: socket.socket) -> Dict[str, Any]:
    header = _recvall(sock, 4)
    ln = int.from_bytes(header, "big")
    if ln < 0 or ln > MAX_FRAME:
        raise ValueError(f"Invalid frame length {ln}")
    raw = _recvall(sock, ln)
    return json.loads(raw.decode("utf-8"))
