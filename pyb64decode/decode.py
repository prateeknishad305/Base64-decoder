#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import base64
import bz2
import dis
import gzip
import io
import lzma
import marshal
import re
import sys
import types
import zlib
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
try:
    from clean import clean_source
    from titan import is_titan, unpack_titan
except ImportError:
    from pyb64decode.clean import clean_source
    from pyb64decode.titan import is_titan, unpack_titan

B64_RE = re.compile(
    rb"(?:[A-Za-z0-9+/_\-]{4}){6,}(?:[A-Za-z0-9+/_\-]{2}==|[A-Za-z0-9+/_\-]{3}=)?"
)
PY_MARKERS = (
    b"import ",
    b"from ",
    b"def ",
    b"class ",
    b"exec(",
    b"eval(",
    b"print(",
    b"if __name__",
    b"marshal",
    b"base64",
    b"zlib",
    b"lambda",
    b"return ",
    b"async ",
    b"await ",
)
ZLIB_MAGICS = (b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda")
KNOWN_XOR = (
    0x01, 0x0A, 0x0D, 0x13, 0x17, 0x21, 0x37, 0x42, 0x55, 0x5A,
    0x69, 0x7A, 0x80, 0xAA, 0xAD, 0xBE, 0xC0, 0xDE, 0xEF, 0xFF,
)
B64_ALPHABET = re.compile(rb"^[A-Za-z0-9+/_\-]+={0,2}$")
HEX_ALPHABET = re.compile(rb"^[0-9A-Fa-f]+$")
B32_ALPHABET = re.compile(rb"^[A-Z2-7]+={0,6}$")
_FAIL = object()

WRAPPERS = (
    b"exec(",
    b"eval(",
    b"marshal.loads",
    b"base64.b64decode",
    b"base64.urlsafe_b64decode",
    b"zlib.decompress",
    b"lzma.decompress",
    b"gzip.decompress",
    b"bz2.decompress",
    b"bytes.fromhex",
    b"codecs.decode",
    b"_decrypt(",
    b"TITAN_ENC_",
)


def looks_like_text(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:8192]
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    printable = sum(32 <= b <= 126 or b in (9, 10, 13) for b in sample)
    return printable / max(len(sample), 1) > 0.85


def parse_tree(data: bytes):
    if not looks_like_text(data):
        return None
    try:
        return ast.parse(data.decode("utf-8"))
    except (SyntaxError, UnicodeDecodeError, ValueError):
        return None


def trivial_ast(tree) -> bool:
    if tree is None or not tree.body:
        return True
    if len(tree.body) != 1:
        return False
    node = tree.body[0]
    if isinstance(node, ast.Expr):
        return isinstance(
            node.value,
            (ast.Name, ast.Constant, ast.Str, ast.Num, ast.Bytes, ast.NameConstant),
        )
    return False


def looks_like_python(data: bytes) -> bool:
    tree = parse_tree(data)
    if tree is None or trivial_ast(tree):
        return False
    return True


def ast_ok(data: bytes) -> bool:
    tree = parse_tree(data)
    return tree is not None and not trivial_ast(tree)


def finished_python(data: bytes) -> bool:
    if not ast_ok(data):
        return False
    if is_titan(data):
        return False
    lowered = data[:8000].lower()
    return not any(w in lowered for w in WRAPPERS)


def is_pyc(data: bytes) -> bool:
    if len(data) < 16:
        return False
    return data[2:4] == b"\x0d\x0a"


def marshal_loads_code(data: bytes):
    offsets = [0]
    if is_pyc(data):
        offsets.extend((12, 16))
    for offset in offsets:
        if offset >= len(data):
            continue
        try:
            obj = marshal.loads(data[offset:])
        except Exception:
            continue
        if isinstance(obj, types.CodeType) and obj.co_code:
            return obj, offset
        if isinstance(obj, (bytes, bytearray)) and len(obj) > 8:
            return bytes(obj), offset
        if isinstance(obj, str) and len(obj) > 8:
            return obj.encode("utf-8"), offset
    return None


def score(data: bytes) -> int:
    if not data:
        return 0
    n = 0
    if data[:2] in ZLIB_MAGICS:
        n += 50
    if data[:2] == b"\x1f\x8b":
        n += 50
    if data[:3] == b"BZh":
        n += 50
    if data[:6] == b"\xfd7zXZ\x00":
        n += 50
    if looks_like_python(data):
        n += 80
    if ast_ok(data):
        n += 40
    if marshal_loads_code(data) is not None:
        n += 70
    if is_pyc(data):
        n += 40
    if is_titan(data):
        n += 60
    printable = sum(32 <= b <= 126 or b in (9, 10, 13) for b in data[:2048])
    n += printable // 80
    return n


def xor_bytes(data: bytes, key) -> bytes:
    if isinstance(key, int):
        return bytes(b ^ (key & 0xFF) for b in data)
    kb = key if isinstance(key, (bytes, bytearray)) else str(key).encode()
    if not kb:
        return data
    klen = len(kb)
    return bytes(b ^ kb[i % klen] for i, b in enumerate(data))


def compact_ws(data: bytes) -> bytes:
    return re.sub(rb"\s+", b"", data.strip())


def try_b64(data: bytes):
    raw = compact_ws(data)
    if len(raw) < 12:
        return None
    if not B64_ALPHABET.fullmatch(raw):
        return None
    pad = (-len(raw.strip(b"="))) % 4
    padded = raw if raw.endswith(b"=") else raw + b"=" * pad
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            if decoder is base64.b64decode:
                try:
                    out = decoder(padded, validate=False)
                except TypeError:
                    out = decoder(padded)
            else:
                out = decoder(padded)
        except Exception:
            continue
        if out and out != raw:
            return out
    return None


def try_b32(data: bytes):
    raw = compact_ws(data).upper()
    if len(raw) < 16 or not B32_ALPHABET.fullmatch(raw):
        return None
    try:
        out = base64.b32decode(raw)
    except Exception:
        return None
    return out or None


def try_b85(data: bytes):
    raw = compact_ws(data)
    if len(raw) < 16:
        return None
    for decoder in (base64.b85decode, base64.a85decode):
        try:
            out = decoder(raw)
        except Exception:
            continue
        if out and out != raw:
            return out
    return None


def try_b16(data: bytes):
    raw = compact_ws(data).upper()
    if len(raw) < 16 or len(raw) % 2 or not HEX_ALPHABET.fullmatch(raw):
        return None
    try:
        out = base64.b16decode(raw)
    except Exception:
        return None
    return out or None


def try_hex(data: bytes):
    raw = compact_ws(data)
    if len(raw) < 16 or len(raw) % 2 or not HEX_ALPHABET.fullmatch(raw):
        return None
    try:
        out = bytes.fromhex(raw.decode("ascii"))
    except Exception:
        return None
    return out or None


def try_compress(data: bytes):
    magic2 = data[:2]
    if magic2 in ZLIB_MAGICS:
        try:
            return zlib.decompress(data)
        except Exception:
            pass
        try:
            return zlib.decompress(data, -15)
        except Exception:
            return None
    if magic2 == b"\x1f\x8b":
        try:
            return gzip.decompress(data)
        except Exception:
            return None
    if data[:3] == b"BZh":
        try:
            return bz2.decompress(data)
        except Exception:
            return None
    if data[:6] == b"\xfd7zXZ\x00" or data[:4] == b"]\x00\x00\x00":
        try:
            return lzma.decompress(data)
        except Exception:
            return None
    return None


def rot13_bytes(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        if 65 <= b <= 90:
            out.append((b - 65 + 13) % 26 + 65)
        elif 97 <= b <= 122:
            out.append((b - 97 + 13) % 26 + 97)
        else:
            out.append(b)
    return bytes(out)


def shift_bytes(data: bytes, n: int) -> bytes:
    return bytes((b + n) % 256 for b in data)


def code_source_hint(code: types.CodeType):
    for const in code.co_consts:
        if isinstance(const, str) and len(const) > 40:
            encoded = const.encode("utf-8", errors="replace")
            if looks_like_python(encoded):
                return encoded
        if isinstance(const, bytes) and len(const) > 40:
            if looks_like_python(const) or try_compress(const) or try_b64(const):
                return const
        if isinstance(const, types.CodeType):
            nested = code_source_hint(const)
            if nested:
                return nested
    return None


def disassemble(code: types.CodeType) -> bytes:
    buf = io.StringIO()
    buf.write("# marshal code object\n")
    buf.write(
        "# co_filename=%r co_name=%r co_firstlineno=%s\n"
        % (code.co_filename, code.co_name, code.co_firstlineno)
    )
    buf.write("# co_names=%r\n" % (code.co_names,))
    buf.write("# co_consts=%r\n" % (code.co_consts,))
    dis.dis(code, file=buf)
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            buf.write("\n# nested %s\n" % const.co_name)
            dis.dis(const, file=buf)
    return buf.getvalue().encode("utf-8")


def literal_value(node):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Str):
        return node.s
    if isinstance(node, ast.Bytes):
        return node.s
    if isinstance(node, ast.Num):
        return node.n
    if isinstance(node, ast.NameConstant):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.Str):
                parts.append(value.s)
            else:
                return None
        return "".join(parts)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        v = literal_value(node.operand)
        if isinstance(v, (int, float)):
            return -v
    if isinstance(node, (ast.List, ast.Tuple)):
        items = []
        for elt in node.elts:
            val = eval_node(elt)
            if val is _FAIL:
                return None
            items.append(val)
        return items if isinstance(node, ast.List) else tuple(items)
    return None


def _codecs_decode(args, kwargs):
    import codecs

    return codecs.decode(*args, **kwargs)


SAFE_ATTR = {
    ("base64", "b64decode"): lambda a, k: base64.b64decode(*a, **k),
    ("base64", "standard_b64decode"): lambda a, k: base64.standard_b64decode(*a, **k),
    ("base64", "urlsafe_b64decode"): lambda a, k: base64.urlsafe_b64decode(*a, **k),
    ("base64", "b16decode"): lambda a, k: base64.b16decode(*a, **k),
    ("base64", "b32decode"): lambda a, k: base64.b32decode(*a, **k),
    ("base64", "b85decode"): lambda a, k: base64.b85decode(*a, **k),
    ("base64", "a85decode"): lambda a, k: base64.a85decode(*a, **k),
    ("zlib", "decompress"): lambda a, k: zlib.decompress(*a, **k),
    ("gzip", "decompress"): lambda a, k: gzip.decompress(*a, **k),
    ("lzma", "decompress"): lambda a, k: lzma.decompress(*a, **k),
    ("bz2", "decompress"): lambda a, k: bz2.decompress(*a, **k),
    ("marshal", "loads"): lambda a, k: marshal.loads(*a, **k),
    ("codecs", "decode"): _codecs_decode,
}


def eval_node(node):
    if isinstance(node, ast.Name):
        if node.id in (
            "base64",
            "zlib",
            "gzip",
            "lzma",
            "bz2",
            "marshal",
            "codecs",
            "bytes",
            "bytearray",
        ):
            return node.id
        return _FAIL
    if isinstance(node, ast.Attribute):
        parent = eval_node(node.value)
        if parent is _FAIL:
            return _FAIL
        if isinstance(parent, str):
            return (parent, node.attr)
        return _FAIL
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = eval_node(node.left)
        right = eval_node(node.right)
        if left is _FAIL or right is _FAIL:
            return _FAIL
        try:
            return left + right
        except Exception:
            return _FAIL
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        left = eval_node(node.left)
        right = eval_node(node.right)
        if left is _FAIL or right is _FAIL:
            return _FAIL
        try:
            return left * right
        except Exception:
            return _FAIL
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitXor):
        left = eval_node(node.left)
        right = eval_node(node.right)
        if left is _FAIL or right is _FAIL:
            return _FAIL
        if isinstance(left, int) and isinstance(right, int):
            return left ^ right
        if isinstance(left, (bytes, bytearray)) and isinstance(right, int):
            return xor_bytes(bytes(left), right)
        if isinstance(right, (bytes, bytearray)) and isinstance(left, int):
            return xor_bytes(bytes(right), left)
        return _FAIL
    if isinstance(node, ast.Call):
        return eval_call(node)
    if isinstance(node, ast.GeneratorExp):
        return eval_xor_gen(node)
    if isinstance(node, ast.ListComp):
        fake = ast.GeneratorExp(elt=node.elt, generators=node.generators)
        return eval_xor_gen(fake)
    v = literal_value(node)
    return v if v is not None else _FAIL


def eval_xor_gen(node: ast.GeneratorExp):
    if len(node.generators) != 1 or node.generators[0].ifs:
        return _FAIL
    gen = node.generators[0]
    seq = eval_node(gen.iter)
    if not isinstance(seq, (bytes, bytearray, list, tuple)):
        return _FAIL
    elt = node.elt
    if not isinstance(elt, ast.BinOp) or not isinstance(elt.op, ast.BitXor):
        return _FAIL
    key = None
    if isinstance(elt.left, ast.Name) and elt.left.id == gen.target.id:
        key = eval_node(elt.right)
    elif isinstance(elt.right, ast.Name) and elt.right.id == gen.target.id:
        key = eval_node(elt.left)
    if not isinstance(key, int):
        return _FAIL
    return xor_bytes(bytes(seq), key)


def eval_call(node: ast.Call):
    args = []
    for a in node.args:
        v = eval_node(a)
        if v is _FAIL:
            return _FAIL
        args.append(v)
    kwargs = {}
    for kw in node.keywords:
        if kw.arg is None:
            return _FAIL
        v = eval_node(kw.value)
        if v is _FAIL:
            return _FAIL
        kwargs[kw.arg] = v
    func = node.func
    if isinstance(func, ast.Name) and func.id in ("bytes", "bytearray"):
        try:
            if args and isinstance(args[0], (list, tuple)):
                return bytes(args[0])
            if args and isinstance(args[0], (bytes, bytearray, str)):
                return bytes(*args, **kwargs)
        except Exception:
            return _FAIL
        return _FAIL
    if isinstance(func, ast.Name) and func.id in ("exec", "eval", "compile"):
        return args[0] if args else _FAIL
    if (
        isinstance(func, ast.Attribute)
        and func.attr == "fromhex"
        and isinstance(func.value, ast.Name)
        and func.value.id == "bytes"
    ):
        try:
            src = args[0]
            if isinstance(src, bytes):
                src = src.decode("ascii")
            return bytes.fromhex(src)
        except Exception:
            return _FAIL
    if isinstance(func, ast.Attribute) and func.attr in ("decode", "encode"):
        val = eval_node(func.value)
        if val is _FAIL:
            return _FAIL
        try:
            if func.attr == "decode" and isinstance(val, (bytes, bytearray)):
                return val.decode(args[0] if args else "utf-8")
            if func.attr == "encode" and isinstance(val, str):
                return val.encode(args[0] if args else "utf-8")
        except Exception:
            return _FAIL
        return _FAIL
    target = eval_node(func) if not isinstance(func, ast.Name) else func.id
    if isinstance(target, tuple) and target in SAFE_ATTR:
        try:
            return SAFE_ATTR[target](args, kwargs)
        except Exception:
            return _FAIL
    return _FAIL


def unwrap_exec_ast(text: str):
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return None
    best = None
    best_score = -1

    class Visitor(ast.NodeVisitor):
        def visit_Call(self, node):
            nonlocal best, best_score
            val = eval_node(node)
            blob, sc = _payload_score(val)
            if blob is not None and sc > best_score and blob != text.encode("utf-8"):
                best = blob
                best_score = sc
            self.generic_visit(node)

        def visit_Assign(self, node):
            nonlocal best, best_score
            val = eval_node(node.value)
            blob, sc = _payload_score(val)
            if blob is not None and sc > best_score and len(blob) > 16:
                best = blob
                best_score = sc
            self.generic_visit(node)

    Visitor().visit(tree)
    return best


def _payload_score(val):
    if val is _FAIL or val is None:
        return None, -1
    if isinstance(val, types.CodeType):
        hint = code_source_hint(val)
        return (hint if hint is not None else val), 1000
    if isinstance(val, str):
        blob = val.encode("utf-8", errors="replace")
        return blob, score(blob)
    if isinstance(val, (bytes, bytearray)):
        blob = bytes(val)
        return blob, score(blob)
    return None, -1


def extract_b64_blob(data: bytes):
    blobs = sorted(set(B64_RE.findall(data)), key=len, reverse=True)
    for blob in blobs[:16]:
        decoded = try_b64(blob)
        if decoded is None:
            continue
        if (
            score(decoded) >= 40
            or try_compress(decoded) is not None
            or marshal_loads_code(decoded) is not None
            or is_titan(decoded)
        ):
            return decoded
    return None


def useful_payload(data: bytes) -> bool:
    if ast_ok(data):
        return True
    if try_compress(data) is not None:
        return True
    if marshal_loads_code(data) is not None:
        return True
    decoded = try_b64(data)
    if decoded is not None and score(decoded) > 40:
        return True
    return False


def auto_xor(data: bytes):
    if len(data) < 8:
        return None
    if finished_python(data):
        return None
    best = None
    best_key = None
    best_sc = 0
    for key in KNOWN_XOR:
        out = xor_bytes(data, key)
        if not useful_payload(out):
            continue
        sc = score(out)
        if ast_ok(out):
            sc += 40
        if sc > best_sc:
            best = out
            best_key = key
            best_sc = sc
            if ast_ok(out):
                return best, best_key
    if best is None:
        return None
    if best_sc < 80:
        return None
    return best, best_key


def maybe_shift(data: bytes):
    if looks_like_python(data) or marshal_loads_code(data) is not None:
        return None
    for n in (-7, 7, -13, 13, -1, 1):
        out = shift_bytes(data, n)
        if ast_ok(out) or marshal_loads_code(out) is not None:
            return out, n
    return None


class Result:
    def __init__(self, data: bytes, layers: list):
        self.data = data
        self.layers = layers
        self.code = None


def _to_bytes(current):
    if isinstance(current, bytes):
        return current
    if isinstance(current, bytearray):
        return bytes(current)
    if isinstance(current, str):
        return current.encode("utf-8")
    return None


def unwrap(data: bytes, max_layers: int = 64, xor_key=None, password=None) -> Result:
    layers = []
    current = data
    code_obj = None
    seen = set()
    for _ in range(max_layers):
        raw = _to_bytes(current)
        if raw is not None:
            digest = (len(raw), hash(raw[:64]), hash(raw[-64:]) if len(raw) >= 64 else 0)
            if digest in seen:
                break
            seen.add(digest)
        if isinstance(current, (bytes, bytearray)) and is_titan(bytes(current)):
            payload, tag = unpack_titan(bytes(current), password=password)
            current = payload
            layers.append(tag)
            continue
        if isinstance(current, types.CodeType):
            code_obj = current
            hint = code_source_hint(current)
            if hint is not None:
                current = hint
                layers.append("marshal-const")
                continue
            current = disassemble(current)
            layers.append("marshal-dis")
            break
        current = _to_bytes(current)
        if current is None:
            break
        if finished_python(current):
            break
        nxt = try_compress(current)
        if nxt is not None:
            current = nxt
            layers.append("compress")
            continue
        loaded = marshal_loads_code(current)
        if loaded is not None:
            obj, offset = loaded
            current = obj
            if isinstance(obj, types.CodeType):
                layers.append("marshal@%d" % offset)
            else:
                layers.append("marshal-bytes")
            continue
        nxt = try_b64(current)
        if nxt is not None and (score(nxt) > score(current) or not ast_ok(current)):
            current = nxt
            layers.append("base64")
            continue
        nxt = try_hex(current)
        if nxt is not None and score(nxt) > score(current):
            current = nxt
            layers.append("hex")
            continue
        nxt = try_b16(current)
        if nxt is not None and score(nxt) > score(current):
            current = nxt
            layers.append("base16")
            continue
        nxt = try_b32(current)
        if nxt is not None and score(nxt) > score(current):
            current = nxt
            layers.append("base32")
            continue
        nxt = try_b85(current)
        if nxt is not None and score(nxt) > score(current) and not ast_ok(current):
            current = nxt
            layers.append("base85")
            continue
        if looks_like_text(current):
            text = current.decode("utf-8", errors="replace")
            inner = unwrap_exec_ast(text)
            if inner is not None and inner != current:
                current = inner
                layers.append("ast")
                continue
            blob = extract_b64_blob(current)
            if blob is not None:
                current = blob
                layers.append("b64-blob")
                continue
            rot = rot13_bytes(current)
            if ast_ok(rot) and rot != current:
                current = rot
                layers.append("rot13")
                continue
            rev = current[::-1]
            if looks_like_python(rev) and not looks_like_python(current):
                current = rev
                layers.append("reverse")
                continue
        if xor_key is not None:
            current = xor_bytes(current, xor_key)
            layers.append("xor-key")
            xor_key = None
            continue
        x = auto_xor(current)
        if x is not None:
            current, key = x
            layers.append("xor-0x%02x" % key)
            continue
        sh = maybe_shift(current)
        if sh is not None:
            current, n = sh
            layers.append("shift-%d" % n)
            continue
        break
    if isinstance(current, types.CodeType):
        code_obj = current
        current = disassemble(current)
    payload = _to_bytes(current) or b""
    if ast_ok(payload):
        payload = clean_source(payload)
        layers.append("clean")
    res = Result(payload, layers)
    res.code = code_obj
    return res


def parse_xor_key(value: str):
    if value is None:
        return None
    value = value.strip()
    if value.lower().startswith("0x"):
        hexpart = value[2:]
        if len(hexpart) <= 2:
            return int(value, 16) & 0xFF
        if len(hexpart) % 2:
            hexpart = "0" + hexpart
        return bytes.fromhex(hexpart)
    if value.isdigit():
        return int(value) & 0xFF
    try:
        return bytes.fromhex(value)
    except ValueError:
        return value.encode("utf-8")


def _titan_stub(payload: bytes, method: int) -> bytes:
    body = [
        "# TitanCrypt Encrypted Python Script",
        "import base64,zlib,lzma,struct,hashlib,marshal,codecs",
        '_h="SxxIH00cHhgfSxtIGExMQxgfGBlMH0NLTUJITx5JTEw="',
        "_t=base64.b64decode(_h)",
        "_pw=''.join(chr(b^0x7A) for b in _t)",
        "_DATA=%r" % base64.b64encode(payload).decode("ascii"),
        "_METHOD=%d" % method,
        "_MARSHAL=False",
        "def _decrypt(d,m,pw):",
        "    import struct",
        "    if d[:13]==b'TITAN_ENC_V1_':",
        "        pw_len=struct.unpack('<H',d[15:17])[0]",
        "        c=d[17+pw_len:]",
        "    else:c=d",
        "    if m==1:return base64.b64decode(c)",
        "    if m==3:return bytes(b^0x5A for b in c)",
        "    return c",
        "try:",
        "    _raw=_decrypt(base64.b64decode(_DATA),_METHOD,_pw)",
        "    exec(_raw.decode() if isinstance(_raw,bytes) else _raw)",
        "except Exception as _e:",
        "    raise",
    ]
    return "\n".join(body).encode("utf-8")


def selftest() -> int:
    src = b"print('ok-layer')\n"
    dumped = marshal.dumps(compile(src, "<t>", "exec"))
    xor_src = xor_bytes(src, 0x5A)
    cases = [
        ("b64", base64.b64encode(src), b"ok-layer"),
        ("zlib+b64", base64.b64encode(zlib.compress(src)), b"ok-layer"),
        ("xor", xor_src, b"ok-layer"),
        ("marshal+zlib+b64", base64.b64encode(zlib.compress(dumped)), b"ok-layer"),
        (
            "exec-b64",
            ("exec(base64.b64decode(%r))\n" % base64.b64encode(src).decode("ascii")).encode(),
            b"ok-layer",
        ),
        (
            "exec-marshal",
            (
                "exec(marshal.loads(base64.b64decode(%r)))\n"
                % base64.b64encode(dumped).decode("ascii")
            ).encode(),
            b"ok-layer",
        ),
        ("xor-b64", base64.b64encode(xor_src), b"ok-layer"),
        ("titan-b64", _titan_stub(base64.b64encode(src), method=1), b"ok-layer"),
        ("titan-xor", _titan_stub(xor_bytes(src, 0x5A), method=3), b"ok-layer"),
        (
            "nested-titan",
            ("exec(base64.b64decode(%r))\n" % base64.b64encode(_titan_stub(base64.b64encode(src), 1)).decode("ascii")).encode(),
            b"ok-layer",
        ),
    ]
    failed = 0
    for name, blob, needle in cases:
        out = unwrap(blob)
        body = out.data
        if needle not in body:
            print("FAIL", name, out.layers, body[:160], file=sys.stderr)
            failed += 1
        else:
            print("PASS", name, "->", ",".join(out.layers) or "none", file=sys.stderr)
    return 1 if failed else 0


def parse_args():
    p = argparse.ArgumentParser(
        description="Unwrap layered Python encoding and dump cleaned source."
    )
    p.add_argument("input", nargs="?", help="Obfuscated .py / payload file")
    p.add_argument("-o", "--output", help="Write cleaned Python to path")
    p.add_argument("--max-layers", type=int, default=64)
    p.add_argument("--xor-key", help="XOR key: 0x5A, 90, hex bytes, or ascii")
    p.add_argument("--password", help="Override TitanCrypt password already in the stub")
    p.add_argument("--no-clean", action="store_true", help="Skip ast.unparse cleanup")
    p.add_argument("--selftest", action="store_true")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if args.selftest:
        return selftest()
    if not args.input:
        print("error: input file required", file=sys.stderr)
        return 1
    path = Path(args.input)
    if not path.is_file():
        print("error: file not found: %s" % path, file=sys.stderr)
        return 1
    data = path.read_bytes()
    key = parse_xor_key(args.xor_key) if args.xor_key else None
    result = unwrap(
        data,
        max_layers=args.max_layers,
        xor_key=key,
        password=args.password,
    )
    info = " -> ".join(result.layers) if result.layers else "none"
    print("# layers: %s" % info, file=sys.stderr)
    out = result.data
    if args.no_clean and ast_ok(out):
        pass
    elif ast_ok(out) and (not result.layers or result.layers[-1] != "clean"):
        out = clean_source(out)
    if not out.endswith(b"\n"):
        out += b"\n"
    if args.output:
        Path(args.output).write_bytes(out)
        print("# wrote %s (%d bytes)" % (args.output, len(out)), file=sys.stderr)
    else:
        sys.stdout.buffer.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
