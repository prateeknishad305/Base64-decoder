#!/usr/bin/env python3
from __future__ import annotations

import base64
import marshal
import re
import types

TITAN_MARKERS = (
    b"TitanCrypt Encrypted Python Script",
    b"TITAN_ENC_V1_",
    b"TITAN_ENC_V2_",
    b"def _decrypt(",
    b"_DATA=",
    b"_METHOD=",
)

_EXEC_PATTERNS = (
    "\ntry:\n    _raw=_decrypt",
    "\ntry:\n    _raw = _decrypt",
    "\ntry:\n\t_raw=_decrypt",
    "\ntry:\n\t_raw = _decrypt",
    "\n_raw=_decrypt(base64.b64decode(_DATA)",
    "\n_raw = _decrypt(base64.b64decode(_DATA)",
    "\n_raw=_decrypt(_DATA",
    "\n_raw = _decrypt(_DATA",
    "\nexec(_decrypt(",
    "\nexec(_raw",
    "\nexec(marshal.loads(_raw",
    "\nexec( marshal.loads(_raw",
)


def is_titan(data: bytes) -> bool:
    if not data or not isinstance(data, (bytes, bytearray)):
        return False
    blob = bytes(data)
    hits = sum(1 for marker in TITAN_MARKERS if marker in blob)
    return hits >= 2 and b"_DATA=" in blob and b"_METHOD=" in blob and b"_decrypt" in blob


def _cut_exec_tail(text: str) -> str:
    cuts = []
    for marker in _EXEC_PATTERNS:
        idx = text.find(marker)
        if idx != -1:
            cuts.append(idx)
    start = 0
    while True:
        idx = text.find("\ntry:", start)
        if idx == -1:
            break
        chunk = text[idx : idx + 500]
        if "_decrypt" in chunk and ("exec(" in chunk or "_raw" in chunk):
            cuts.append(idx)
        start = idx + 1
    for match in re.finditer(r"\n(?:if\s+__name__\s*==\s*['\"]__main__['\"]\s*:)", text):
        tail = text[match.start() : match.start() + 400]
        if "exec(" in tail or "_decrypt" in tail:
            cuts.append(match.start())
    if not cuts:
        raise ValueError("TitanCrypt exec tail not found")
    return text[: min(cuts)].rstrip() + "\n"


def _need_crypto(text: str) -> bool:
    needles = (
        "Crypto.Cipher",
        "Cryptodome.Cipher",
        "cryptography.fernet",
        "Fernet(",
        "AES.new",
        "ChaCha20",
        "Blowfish",
        "DES3",
    )
    return any(n in text for n in needles)


def _import_crypto() -> None:
    try:
        from Crypto.Cipher import AES, Blowfish, DES3, ChaCha20  # noqa: F401
        from Crypto.Util.Padding import pad, unpad  # noqa: F401
        return
    except Exception:
        pass
    try:
        from Cryptodome.Cipher import AES, Blowfish, DES3, ChaCha20  # noqa: F401
        from Cryptodome.Util.Padding import pad, unpad  # noqa: F401
        return
    except Exception as exc:
        raise RuntimeError(
            "TitanCrypt cipher methods need pycryptodome. "
            "Install: pip install --break-system-packages pycryptodome cryptography"
        ) from exc


def unpack_titan(data: bytes, password=None):
    if not is_titan(data):
        return None
    text = data.decode("utf-8", errors="replace")
    if text.startswith("\ufeff"):
        text = text[1:]
    setup = _cut_exec_tail(text)
    if _need_crypto(setup):
        _import_crypto()
    ns = {"__builtins__": __builtins__}
    exec(compile(setup, "<titan-stub>", "exec"), ns, ns)
    if password is not None:
        ns["_pw"] = password
        ns["password"] = password
    if "_decrypt" not in ns or "_DATA" not in ns or "_METHOD" not in ns:
        raise ValueError("TitanCrypt stub missing _decrypt/_DATA/_METHOD")
    payload = ns["_DATA"]
    if isinstance(payload, str):
        compact = re.sub(r"\s+", "", payload)
        try:
            payload = base64.b64decode(compact)
        except Exception:
            payload = payload.encode("utf-8")
    elif isinstance(payload, bytearray):
        payload = bytes(payload)
    method = ns["_METHOD"]
    pw = ns.get("_pw", ns.get("password", ""))
    decrypt = ns["_decrypt"]
    raw = None
    errors = []
    attempts = []
    if isinstance(payload, bytes):
        attempts.append(payload)
        try:
            attempts.append(base64.b64decode(payload))
        except Exception:
            pass
    else:
        attempts.append(payload)
    for candidate in attempts:
        try:
            raw = decrypt(candidate, method, pw)
            if raw:
                break
        except Exception as exc:
            errors.append(str(exc))
            raw = None
    if raw is None:
        detail = "; ".join(errors[:3]) if errors else "empty payload"
        raise ValueError("TitanCrypt decrypt failed: %s" % detail)
    if ns.get("_MARSHAL") or ns.get("_USE_MARSHAL"):
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        loaded = marshal.loads(raw)
        return loaded, "titan-marshal-%s" % method
    if isinstance(raw, types.CodeType):
        return raw, "titan-code-%s" % method
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    elif isinstance(raw, bytearray):
        raw = bytes(raw)
    elif not isinstance(raw, bytes):
        raw = str(raw).encode("utf-8")
    return raw, "titan-%s" % method
