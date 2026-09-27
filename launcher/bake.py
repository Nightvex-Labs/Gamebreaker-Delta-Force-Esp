"""DeltaHack: pack + bake helper.

Packs loader/build/dh_loader.exe into launcher/embed/dh_loader.kfpl with a
fresh AES-256 key, then rewrites the KFPL_KEY[32] literal inside
launcher/src/dh_launcher.c.

Two modes:
  (default)    — ZERO-KEY mode. Baked key is left all-zeros so the launcher
                 REQUIRES env DH_KFPL_KEY_B64 / _HEX (or DPAPI-wrapped
                 context.json kfplKey) to decrypt. Admin panel stores the
                 real key. Fresh random key printed for the operator to
                 paste into the site's KFPL KEY form field.
  --bake       — Bake the real key into launcher source (dev/local testing).
                 Anyone with the binary can extract the key from the .rdata
                 section — never ship this to prod.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import secrets
from pathlib import Path

HERE = Path(__file__).resolve().parent
PACK = HERE.parent / "scripts" / "pack_kfpl.py"
INPUT_EXE = HERE.parent / "loader" / "build" / "dh_loader.exe"
OUTPUT_KFPL = HERE / "embed" / "dh_loader.kfpl"
LAUNCHER_C = HERE / "src" / "dh_launcher.c"

ZERO_KEY = bytes(32)


def run_pack_clean_b64() -> bytes:
    """Run packer up to 30 times until the b64 has no + or / characters.
    Admin panel form has an old bug where +/ get truncated on paste."""
    for attempt in range(30):
        r = subprocess.run(
            [sys.executable, str(PACK), str(INPUT_EXE), str(OUTPUT_KFPL)],
            check=True, capture_output=True, text=True,
        )
        m = re.search(r"KFPL key \(hex\):\s+([0-9a-fA-F]{64})", r.stdout)
        if not m:
            raise RuntimeError("could not parse key from pack output")
        key = bytes.fromhex(m.group(1))
        import base64
        b64 = base64.b64encode(key).decode()
        if "+" not in b64 and "/" not in b64:
            print(r.stdout, end="")
            if r.stderr: print(r.stderr, end="", file=sys.stderr)
            print(f"[bake] clean b64 on attempt {attempt+1}")
            return key
    raise RuntimeError("30 attempts, never got a +/-free b64 — statistical anomaly")


def write_key(key: bytes) -> None:
    body_lines = []
    for row in range(4):
        row_bytes = key[row * 8:(row + 1) * 8]
        body_lines.append("    " + ",".join(f"0x{b:02X}" for b in row_bytes) + ",")
    body = "\n".join(body_lines)

    src = LAUNCHER_C.read_text(encoding="utf-8")
    pattern = r"static const uint8_t KFPL_KEY\[32\] = \{[^}]+\};"
    if not re.search(pattern, src, re.S):
        raise RuntimeError("KFPL_KEY[] not found in launcher.c — marker changed?")
    new = re.sub(
        pattern,
        "static const uint8_t KFPL_KEY[32] = {\n" + body + "\n};",
        src, count=1, flags=re.S,
    )
    LAUNCHER_C.write_text(new, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bake", action="store_true",
                    help="bake REAL key into launcher source (dev/local only)")
    args = ap.parse_args()

    if not INPUT_EXE.exists():
        print(f"[bake] {INPUT_EXE} missing — build loader first", file=sys.stderr)
        return 1

    key = run_pack_clean_b64()
    if args.bake:
        write_key(key)
        print(f"[bake] REAL key written into {LAUNCHER_C.name}")
        print("[bake] WARNING — binary now carries decrypt key, anyone can extract")
    else:
        write_key(ZERO_KEY)
        print(f"[bake] ZERO key written into {LAUNCHER_C.name} (admin-panel mode)")
        print()
        print("=" * 72)
        print("  KFPL KEY (paste into site's upload form, KFPL KEY field):")
        print()
        print(f"    hex:    {key.hex()}")
        print()
        import base64
        print(f"    b64:    {base64.b64encode(key).decode()}")
        print()
        print("  Backend must inject env DH_KFPL_KEY_B64/_HEX (or write it into")
        print("  the DPAPI-wrapped launch-context JSON) at Play time.")
        print("=" * 72)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
