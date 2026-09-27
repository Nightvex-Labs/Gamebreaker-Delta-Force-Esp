"""DeltaHack KFPL packer.

Wraps a PE (dh_loader.exe) in an AES-256-GCM container with format:

    Offset  0   Magic     "DHKF"                    4 bytes
    Offset  4   Version   u32 LE = 1                4 bytes
    Offset  8   Nonce                              12 bytes (fresh random)
    Offset 20   Ciphertext length (u64 LE)          8 bytes
    Offset 28   Ciphertext (AES-256-GCM)            N bytes
    Offset 28+N GCM tag                            16 bytes

Magic "DHKF" chosen instead of ABI's "KFPL" so the two families of blob
never accidentally cross-load. Key is 32 bytes (AES-256).

Two modes:
  --key-hex HEX     use a specific 32-byte key (hex-encoded)
  --key-b64 B64     use a specific 32-byte key (base64-encoded)
  (default)         generate a fresh random key, print it, exit — the
                    launcher's build needs the printed key baked in

Usage:
  python scripts/pack_kfpl.py loader/build/dh_loader.exe \
                              launcher/embed/dh_loader.kfpl \
                              --key-hex <hex>
"""
from __future__ import annotations

import base64
import os
import secrets
import struct
import sys

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("[!] pip install cryptography", file=sys.stderr)
    sys.exit(2)

MAGIC = b"DHKF"       # DeltaHack KFPL — distinct from ABI's KFPL family
                       # so blobs from the two products never cross-load.
                       # dh_launcher.c KFPL_MAGIC[4] = {'D','H','K','F'}.
VERSION = 1
NONCE_LEN = 12
TAG_LEN = 16


def pack(payload: bytes, key: bytes) -> bytes:
    nonce = os.urandom(NONCE_LEN)
    gcm = AESGCM(key)
    ct_and_tag = gcm.encrypt(nonce, payload, associated_data=MAGIC)
    ct = ct_and_tag[:-TAG_LEN]
    tag = ct_and_tag[-TAG_LEN:]
    header = MAGIC + struct.pack("<I", VERSION) + nonce + struct.pack("<Q", len(ct))
    return header + ct + tag


def main() -> int:
    args = sys.argv[1:]
    if len(args) < 2:
        print("usage: pack_kfpl.py <input.exe> <output.kfpl> "
              "[--key-hex HEX | --key-b64 B64]", file=sys.stderr)
        return 2

    src, dst = args[0], args[1]
    rest = args[2:]

    key: bytes
    src_desc: str
    if len(rest) == 2 and rest[0] == "--key-hex":
        key = bytes.fromhex(rest[1].strip())
        src_desc = "reused (--key-hex)"
    elif len(rest) == 2 and rest[0] == "--key-b64":
        key = base64.b64decode(rest[1].strip())
        src_desc = "reused (--key-b64)"
    elif rest:
        print(f"[!] unknown args: {rest}", file=sys.stderr)
        return 2
    else:
        key = secrets.token_bytes(32)
        src_desc = "fresh random"

    if len(key) != 32:
        print(f"[!] KFPL key must be 32 bytes, got {len(key)}", file=sys.stderr)
        return 2

    with open(src, "rb") as f:
        payload = f.read()
    blob = pack(payload, key)

    os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
    with open(dst, "wb") as f:
        f.write(blob)

    print(f"[+] packed {src} ({len(payload):,} B) -> {dst} ({len(blob):,} B)")
    print(f"    key source: {src_desc}")
    print(f"    KFPL key (hex):    {key.hex()}")
    print(f"    KFPL key (base64): {base64.b64encode(key).decode()}")
    print()
    print("Next: bake the hex key into launcher/src/dh_launcher.c:")
    print(f'    static const uint8_t KFPL_KEY[32] = {{ 0x{key[0]:02x}, 0x{key[1]:02x}, ... }};')
    print("or regenerate with the SAME key on next pack via:")
    print(f"    python scripts/pack_kfpl.py <in> <out> --key-hex {key.hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
