#!/usr/bin/env python3
"""Unpack TitanCrypt stubs using the password and method already in the file."""

from __future__ import annotations

import marshal
import types

TITAN_MARKERS = (
    b"TitanCrypt Encrypted Python Script",
    b"TITAN_ENC_V1_",
    b"def _decrypt(",
)

EXEC_TAIL = (
    "try:\n    _raw=_decrypt",
    "try:\n    _raw = _decrypt",
    "_raw=_decrypt(base64.b64decode(_DATA)",
    "_raw=_decrypt(base64.b64decode(_DATA)",
)


def is_titan(data: bytes) -> bool:
    hits = sum(1 for m in TITAN_MARKERS if m in data)
    return hits >= 2 and b"_DATA=" in data and b"_METHOD=" in data


def _cut_exec_tail(text: str) -> str:
    cuts = []
    for marker in EXEC_TAIL:
        idx = text.find(marker)
        if idx != -1:
            cuts.append(idx)
    if not cuts:
        idx = text.rfind("try:")
        if idx != -1 and "_decrypt" in text[idx:idx + 200]:
            cuts.append(idx)
    if not cuts:
        raise ValueError("TitanCrypt exec tail not found")
    return text[: min(cuts)]


def _need_crypto(text: str) -> bool:
    return "Crypto.Cipher" in text or "Cryptodome.Cipher" in text or "cryptography.fernet" in text


def _import_crypto():
    try:
        from Crypto.Cipher import AES, Blowfish, DES3, ChaCha20  # noqa: F401
        from Crypto.Util.Padding import unpad, pad  # noqa: F401
        return
    except Exception:
        pass
    try:
        from Cryptodome.Cipher import AES, Blowfish, DES3, ChaCha20  # noqa: F401
        from Cryptodome.Util.Padding import unpad, pad  # noqa: F401
        return
    except Exception as exc:
        raise RuntimeError(
            "TitanCrypt cipher methods need pycryptodome. "
            "Termux: pip install --break-system-packages pycryptodome cryptography"
        ) from exc


def unpack_titan(data: bytes):
    if not is_titan(data):
        return None
    text = data.decode("utf-8", errors="replace")
    setup = _cut_exec_tail(text)
    if _need_crypto(setup):
        _import_crypto()
    ns = {}
    exec(compile(setup, "<titan-stub>", "exec"), ns, ns)
    if "_decrypt" not in ns or "_DATA" not in ns or "_METHOD" not in ns:
        raise ValueError("TitanCrypt stub missing _decrypt/_DATA/_METHOD")
    payload = ns["_DATA"]
    if isinstance(payload, str):
        import base64
        payload = base64.b64decode(payload)
    raw = ns["_decrypt"](payload, ns["_METHOD"], ns.get("_pw", ""))
    if ns.get("_MARSHAL"):
        loaded = marshal.loads(raw)
        return loaded, "titan-marshal-%s" % ns["_METHOD"]
    if isinstance(raw, types.CodeType):
        return raw, "titan-code-%s" % ns["_METHOD"]
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    return raw, "titan-%s" % ns["_METHOD"]
