# pyb64decode

Termux-ready layered unpacker for encoded Python.

Unwraps encoding layers and dumps **cleaned Python source**. It does not crack unknown passwords. TitanCrypt AES/Fernet/ChaCha methods use the password already stored inside the stub.

## Termux (full process)

### 1. Install Termux packages

```bash
pkg update
pkg upgrade
pkg install python git
```

### 2. Clone this repo

```bash
cd ~
git clone https://github.com/prateeknishad305/pyb64decode.git
cd pyb64decode
```

### 3. TitanCrypt cipher packs (AES / Fernet / ChaCha)

Only needed for methods like AES, GCM, Blowfish, DES3, ChaCha, Fernet:

```bash
pip install --break-system-packages pycryptodome cryptography
```

Skip this step for Base64 / Marshal / XOR / zlib files.

### 4. Decode a file

Put the encoded `.py` in Termux (share it, or copy to `~/pyb64decode`).

```bash
python pyb64decode/decode.py encoded.py -o decoded.py
```

Or:

```bash
python -m pyb64decode encoded.py -o decoded.py
```

`decoded.py` is cleaned Python source, not leftover `_DATA` / `_decrypt` stubs.

### 5. TitanCrypt stub

```bash
python pyb64decode/decode.py titan_stub.py -o unpacked.py
```

If the stub has a custom password:

```bash
python pyb64decode/decode.py titan_stub.py --password SECRET -o unpacked.py
```

### 6. Other options

```bash
python pyb64decode/decode.py file.py
python pyb64decode/decode.py file.py --xor-key 0x5A -o out.py
python pyb64decode/decode.py --selftest
```

Prints layers to stderr, writes cleaned Python to stdout or `-o`.

Python 3.8+.

## Layers

- Base64 / urlsafe / base16 / base32 / base85
- zlib, gzip, lzma, bz2
- Marshal (`marshal.loads`, `.pyc` header)
- XOR (auto single-byte or `--xor-key`)
- hex, rot13, reverse, byte shift
- `exec(base64.b64decode(...))` and nested decode AST chains
- TitanCrypt stubs (`_DATA` / `_METHOD` / `_decrypt`) using the password already in the file
- Source cleanup via `ast.unparse` so output is full readable Python

Typical stack:

```text
exec(marshal.loads(zlib.decompress(base64.b64decode(...))))
```
