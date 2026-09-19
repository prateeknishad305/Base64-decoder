# pyb64decode

Termux-ready layered unpacker for encoded Python.

Unwraps encoding layers only. It does not crack passwords or AES/Fernet/cipher packs.

## Layers

- Base64 / urlsafe / base16 / base32 / base85
- zlib, gzip, lzma, bz2
- Marshal (`marshal.loads`, `.pyc` header)
- XOR (auto single-byte or `--xor-key`)
- hex, rot13, reverse, byte shift
- `exec(base64.b64decode(...))` and nested decode AST chains

- TitanCrypt stubs (`_DATA` / `_METHOD` / `_decrypt`) using the password already in the file; dumps source instead of `exec`

Typical stack it can peel:

```text
exec(marshal.loads(zlib.decompress(base64.b64decode(...))))
```

TitanCrypt:

```bash
python pyb64decode/decode.py titan_stub.py -o unpacked.py
```

Cipher methods (AES/Fernet/ChaCha) need:

```bash
pip install --break-system-packages pycryptodome cryptography
```

## Termux

```bash
pkg update
pkg install python
python pyb64decode/decode.py obfuscated.py -o decoded.py
```

Or:

```bash
python -m pyb64decode obfuscated.py -o decoded.py
```

## Usage

```bash
python pyb64decode/decode.py file.py
python pyb64decode/decode.py file.py -o out.py
python pyb64decode/decode.py file.py --xor-key 0x5A -o out.py
python pyb64decode/decode.py --selftest
```

No extra pip packages. Python 3.8+.
