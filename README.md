# IDAChef

A [CyberChef](https://github.com/gchq/CyberChef)-style recipe/operation toolkit embedded in **IDA Pro 9.x**.
Build multi-step data transformation chains — encoding, encryption, compression,
hashing, extraction — and run them directly against bytes or strings from your
IDA database.  Patch the result back into the binary or drop it as a comment.

```
┌──────────────┬──────────────────┬─────────────────────────────┐
│  Operations  │     Recipe       │         I/O Panel           │
│  (search)    │                  │                             │
│              │  ┌─ From Hex ──┐ │  Input:  5e 73 68 7d 6c... │
│  Data format │  │  XOR  [0x55] │ │  [Get Selected Bytes]      │
│  ▸ From Hex  │  │  ADD  [3]    │ │  [Get String @ Cursor]     │
│  ▸ To Hex    │  └─────────────┘ │  [From Clipboard]           │
│  ▸ From B64  │                  │                             │
│  ...         │  [Up] [Down]    │  [✓ Auto Bake]  [Bake!]    │
│              │  [Remove][Clear] │                             │
│  Encryption  │                  │  Output:  4b 58 87 7f e8    │
│  ▸ XOR       │  Arguments:      │  [Copy] [Output → Input]    │
│  ▸ AES Dec   │  Key: [0x55   ] │                             │
│  ...         │                  │  Address: [0x140001000]     │
│              │                  │  [Patch Bytes] [Set Comment] │
└──────────────┴──────────────────┴─────────────────────────────┘
```

## Features

- **285 operations** across 12 categories — encodings, ciphers, compression,
  hashing, extraction, networking, code formatting, and more
- **Dockable IDA widget** (`Ctrl-Alt-C`) — operation browser, recipe builder,
  and I/O panel all in one window
- **Live "Auto Bake"** — every parameter change instantly recomputes the full
  recipe chain
- **Direct IDA integration** — pull selected bytes, grab the string under your
  cursor, patch output back into the binary, or set comments
- **Formula expressions** — chain byte-level operations in a single step:
  `FromHex+XOR(0x55)+ADD(3)` or `FromBase64+NOT+ROL(3)`
- **Auto-growing argument fields** — monospace fields that expand to fit your
  key/IV/salt, with live byte-length hints and AES key-size detection
- **Zero-dependency core** — hex, Base64/32/85, XOR, gzip/zlib/lzma, SHA*,
  CRC, regex extractors, and 100+ more ops use **only the Python standard
  library**; AES/DES/RC4 available with `pycryptodome` (optional)

## Install

1. Copy **both** `idachef_plugin.py` and the `idachef/` folder into your IDA
   plugins directory:

   | OS      | Path                                                        |
   |---------|-------------------------------------------------------------|
   | Windows | `%APPDATA%\Hex-Rays\IDA Pro\plugins\`                      |
   | macOS   | `~/Library/Application Support/Hex-Rays/IDA Pro/plugins/`  |
   | Linux   | `~/.idapro/plugins/`                                       |

   ```
   plugins/
     idachef_plugin.py
     idachef/
       __init__.py
       core/
         __init__.py
         dish.py
         formula.py
         logger.py
         operation.py
         recipe.py
         utils.py
       operations/
         __init__.py
         arithmetic.py
         ciphers.py
         codeformat.py
         compression.py
         encoding.py
         extractors.py
         hashing.py
         language.py
         networking.py
         other.py
         publickey.py
         textutils.py
       ui/
         __init__.py
         chef_widget.py
         qt_compat.py
   ```

2. (Optional) For AES/DES/RC4 encryption: install `pycryptodome` into IDA's Python:
   ```bash
   "<ida>/python3/python.exe" -m pip install pycryptodome
   ```
   Everything else — Base64/32/85, hex, XOR, ROT13/47, gzip/zlib/bzip2/lzma,
   MD5/SHA*, CRC, HMAC, extractors — works with the standard library alone.

3. Restart IDA (or `Edit → Plugins → IDAChef` / `Ctrl-Alt-C`).

## Usage

### Opening
**Edit → Plugins → IDAChef** or press **Ctrl-Alt-C**.

### Three-panel layout

- **Left — Operation Browser**: searchable, categorised tree. Double-click an
  operation to add it to your recipe. Type in the search box to filter by
  name, category, or description.

- **Centre — Recipe**: ordered list of operations. Click a step to edit its
  arguments. Use **Up** / **Down** / **Remove** / **Clear** buttons to
  rearrange or reset. Arguments update live as you type (with **Auto Bake**
  enabled).

- **Right — I/O Panel**:
  - **Input**: paste text directly, or pull data from IDA:
    - **Get Selected Bytes** — reads the current Hex View / disassembly
      selection and displays it as a hex string
    - **Get String @ Cursor** — reads the string literal at the current
      cursor position
    - **From Clipboard** — pastes clipboard content
  - **Output**: displays the final baked result in your chosen format
    (Auto hex/text, Hex, UTF-8, Latin-1, Base64, Decimal Bytes)
  - **Actions**:
    - **Copy Output** to clipboard
    - **Output → Input** — feed the result back as new input
    - **Patch Bytes at Address** — write output bytes to the specified
      address in the IDA database
    - **Set Comment at Address** — set the output text as a comment at the
      specified address

### Input parsing

The input text is treated as **plain text** (with `\xHH` escape support).
Use explicit recipe steps — `From Hex`, `From Base64`, `From Binary`, etc. —
to decode your input before further processing.

### IDA Output Window logging

Each bake prints three lines to IDA's output window:

```
Input: 5e6877497d7d71526c776d536c707c6c
Step 1 'From Hex' -> ^hwI}}qRlwmSlp|l
Step 2 'XOR' -> KX...
Result: KX...
```

- **Input**: the raw input text (or decoded byte string from IDA)
- **Step N 'Operation'**: the output **after** each recipe step
- **Result**: the final output

All byte content is printed as decoded text (UTF-8 with Latin-1 fallback),
truncated at 300 characters. Errors include the step index and exception
message.

## Formula expressions

The **Formula (compound)** operation lets you chain multiple byte-level
operations in a single recipe step using an expression syntax:

```
FromHex+XOR(0x55)+ADD(3)      — decode hex, XOR with 0x55, add 3 (mod 256)
FromBase64+NOT+ROL(3)         — decode base64, bitwise NOT, rotate left 3
XOR(0xaa)+SHR(2)+AND(0x7f)   — XOR then shift-right then mask
```

**Supported byte-level ops**: `XOR`, `ADD`, `SUB`, `AND`, `OR`, `NOT`,
`ROL`, `ROR`, `SHL`, `SHR`, `MUL`, `MOD`

**Optional `From` prefix**: `FromHex` or `FromBase64` (decodes the entire
input before byte-level operations are applied).  If no prefix is given,
input bytes are used as-is.

Keys in `XOR`/`ADD`/`SUB`/`AND`/`OR`/`MUL`/`MOD` can be hex (`0xNN`) or
decimal integers.  Multi-byte hex keys are cyclically repeated.

## Operations by category — 285 total

### Data format (50)
To/From: Hex, Hexdump, Base64, Base32, Base45, Base85, Base58, Base62,
Binary, Octal, Decimal, Float, Charcode.  URL Encode/Decode, HTML Entity,
Morse Code, Quoted-Printable.  Swap Endianness, Escape/Unescape String,
Escape/Unescape Unicode, Punycode, BCD, Hex Content.  CSV↔JSON,
Unicode Normalisation, Text↔Integer Conversion, Generate UUID.

### Encryption / Encoding (50)
XOR, XOR Brute Force (scoring + crib), ROT13/ROT13 Brute Force,
ROT47/ROT47 Brute Force, ROT8000, ROR13, Atbash, Vigenère Encode/Decode,
Bit Shift Left/Right.  RC4/RC4 Drop.  AES Encrypt/Decrypt (CBC/ECB/CTR/GCM),
AES Key Wrap/Unwrap.  DES/3DES Encrypt/Decrypt.  Blowfish Encrypt/Decrypt.
RC2 Encrypt/Decrypt.  ChaCha20.  TEA/XTEA/XXTEA Encrypt/Decrypt.
Substitute, Affine/A1Z26/Rail Fence/Bacon/Bifid Cipher Encode/Decode,
Caesar Box.  PBKDF2/HKDF key derivation.  Bcrypt, Scrypt.

### Compression (19)
Gzip/Gunzip, Zlib Deflate/Inflate, Raw Deflate/Inflate, Bzip2 Compress/
Decompress, LZMA Compress/Decompress.  Tar/Untar, Zip/Unzip.  LZ4 Compress/
Decompress, LZString Compress/Decompress, LZNT1 Decompress.

### Hashing (33)
MD2, MD4, MD5, SHA0, SHA1, SHA224, SHA256, SHA384, SHA512, SHA2 (unified),
SHA3-224/256/384/512, SHA3 (unified), Keccak, RIPEMD160, BLAKE2b, BLAKE2s.
CRC16 (CCITT/IBM), CRC32, CRC-8/16/32 (unified), Adler32, Fletcher Checksum,
TCP/IP Checksum, XOR Checksum, Luhn Checksum, Parity Bit.  HMAC, CMAC,
MurmurHash3, NT Hash, LM Hash.  Entropy, Frequency Distribution,
Analyse Hash.

### Utils (35)
Reverse, To Upper/Lower/Swap/Alternating/Change Case.  Remove Whitespace/
Null Bytes/ANSI Escape Codes/Line Numbers/Diacritics.  Find/Replace (regex),
Regular Expression, Sort, Shuffle, Unique, Split, Filter.  Head, Tail,
Drop/Take Bytes, Pad Lines, Add Line Numbers, Count Occurrences.
Diff, Hamming/Levenshtein Distance.  UNIX Timestamp↔Date, Parse DateTime,
Get Time.  JWT Decode.  Index of Coincidence, Chi Square.

### Extractors (13)
Extract: IPv4/IPv6, URLs, Emails, Domains, Hex Strings, MAC addresses,
Hashes, File Paths, Dates.  Custom Regex (list + count), Strings (ASCII +
UTF-16LE), RAKE keyword extraction.

### Networking (17)
Defang/Refang IP & URL.  Format MAC Address (with/without : or -).
Parse IPv6, IPv6 Expand/Compress.  CIDR to IP Range, IP Range to CIDR.
IPv4→Decimal, Decimal→IPv4.  Parse URI, URL Decode/Encode.

### Code tidy (14)
JSON Beautify/Minify, XML Beautify/Minify, SQL Beautify/Minify,
CSS Beautify/Minify, JavaScript Beautify/Minify, Strip HTML Tags,
Generic Code Beautify, PHP Serialize/Deserialize.

### Arithmetic / Logic (24)
Sum, Subtract, Multiply, Divide, Mean, Median, Standard Deviation.
Extended GCD, Modular Inverse.  Set Union/Intersection/Difference/
Symmetric Difference.  Bitwise AND/OR/NOT, ADD/SUB (mod 256), MOD.
Bit Shift Left/Right, Rotate Left/Right.  **Formula (compound)** — chain
byte-level operations with FromHex/FromBase64 prefix support.

### Language (7)
To/From NATO Phonetic Alphabet, Convert Leet Speak, Encode/Decode Text,
Unicode Text Format, Escape Smart Characters.

### Other (10)
Pseudo-Random Number/Prime Generator, De Bruijn Sequence, Cyclic Pattern
Generator, Index of Coincidence, Chi Square, Disassemble x86 (capstone),
Generate Lorem Ipsum, Haversine Distance, HTML to Text.

### Public Key (13)
RSA Encrypt/Decrypt/Sign/Verify, Generate RSA Key Pair, Public Key from
Certificate/Private Key.  Parse X.509, ASN.1 Hex Dump, PEM→Hex/Hex→PEM.
PGP Encrypt/Decrypt/Verify.

## Argument UI

- **Text/number fields** use `AutoGrowLineEdit` — a monospace field that
  grows to fit the content (up to 520px), so a 64-char hex key or long XOR
  string is fully visible.
- **Key/IV/Nonce/Salt fields** show a live hint: `"32 chars → 16 bytes as Hex
  (AES-128 / DES3-ok)"` — highlighted green when the byte count matches a
  recognised key size.
- **Short option lists** (≤ 6 choices, e.g. CBC/ECB/CTR/GCM) render as
  **radio buttons** instead of a dropdown — the current selection and all
  alternatives are visible at a glance.

## Extending

Add a new operation by subclassing `idachef.core.operation.Operation`:

```python
from ..core.operation import Operation

class MyOp(Operation):
    name = "My Operation"
    category = "Utils"
    description = "Does something useful."
    args = [
        {"name": "Key", "type": "string", "value": ""},
        {"name": "Mode", "type": "option", "value": "Fast",
         "options": ["Fast", "Slow"]},
    ]

    def _run(self, data, args):
        key = self.get_arg(args, "Key", "")
        # ... transform data ...
        return result
```

Add it to the `OPERATIONS` list in the relevant `idachef/operations/*.py`
file (or create a new file and register it in `__init__.py`). It appears
in the browser automatically — no UI code needed.

## Architecture

```
idachef/
├── core/                 # Pipeline engine
│   ├── operation.py      #   Base Operation class
│   ├── recipe.py         #   Recipe chain runner + BakeResult
│   ├── dish.py           #   bytes ↔ str conversion helpers
│   ├── formula.py        #   Compound formula parser (FromHex+XOR+ADD…)
│   ├── utils.py          #   Shared utilities (key_bytes, bytewise_op, …)
│   └── logger.py         #   IDA output window / fallback logger
├── operations/           # 285 operation classes, 12 category modules
│   └── __init__.py       #   Registry + search
├── ui/
│   ├── chef_widget.py    #   Main dockable widget (operation browser,
│   │                       recipe panel, I/O panel)
│   └── qt_compat.py      #   PyQt5 ↔ PySide6 compatibility layer
└── __init__.py
```

The architecture mirrors CyberChef's `Operation.mjs` → `Recipe.mjs` →
`Dish.mjs` pipeline: each operation's output becomes the next step's input;
if any step fails, baking stops and the partial output + error are reported.

## Testing

157 automated tests covering encoding, hashing, ciphers, arithmetic, utility
operations, and formula expressions:

```bash
cd /path/to/IDAChef
python tests/run_all.py
```

## Compatibility

- **IDA Pro 9.0** (PyQt5) and **9.2+** (PySide6) — `qt_compat.py` handles
  both automatically
- **Python 3.8+**

## Disclaimer

This is a from-scratch Python re-implementation inspired by CyberChef's
design and operation set; no CyberChef source code is included or reproduced.
CyberChef is © UK Crown Copyright / GCHQ, licensed under Apache-2.0 —
see https://github.com/gchq/CyberChef.