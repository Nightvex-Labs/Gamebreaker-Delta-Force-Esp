"""Pack + bake helper for launcher build.

Runs pack_kfpl.py with a fresh random key, then rewrites the KFPL_KEY[]
array inside src/dh_launcher.c to match.

Call from launcher/ directory (build_full.bat wraps this).
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PACK = HERE.parent / "scripts" / "pack_kfpl.py"
INPUT_EXE = HERE.parent / "loader" / "build" / "dh_loader.exe"
OUTPUT_KFPL = HERE / "embed" / "dh_loader.kfpl"
LAUNCHER_C = HERE / "src" / "dh_launcher.c"


def run_pack() -> bytes:
    """Run the packer, return the 32-byte key it printed."""
    r = subprocess.run(
        [sys.executable, str(PACK), str(INPUT_EXE), str(OUTPUT_KFPL)],
        check=True, capture_output=True, text=True,
    )
    print(r.stdout, end="")
    if r.stderr:
        print(r.stderr, end="", file=sys.stderr)

    # Parse a line like: "    KFPL key (hex):    <64 hex chars>"
    m = re.search(r"KFPL key \(hex\):\s+([0-9a-fA-F]{64})", r.stdout)
    if not m:
        raise RuntimeError("could not parse key from pack output")
    return bytes.fromhex(m.group(1))


def bake_key(key: bytes) -> None:
    """Rewrite the KFPL_KEY[32] literal inside dh_launcher.c."""
    body_lines = []
    for row in range(4):
        row_bytes = key[row * 8:(row + 1) * 8]
        body_lines.append("    " + ",".join(f"0x{b:02X}" for b in row_bytes) + ",")
    body = "\n".join(body_lines)

    src = LAUNCHER_C.read_text(encoding="utf-8")
    new = re.sub(
        r"static const uint8_t KFPL_KEY\[32\] = \{[^}]+\};",
        "static const uint8_t KFPL_KEY[32] = {\n" + body + "\n};",
        src, count=1, flags=re.S,
    )
    if new == src:
        raise RuntimeError("KFPL_KEY[] not found in launcher.c — marker changed?")
    LAUNCHER_C.write_text(new, encoding="utf-8")
    print(f"[bake] wrote KFPL_KEY[32] into {LAUNCHER_C.name}")


def main() -> int:
    if not INPUT_EXE.exists():
        print(f"[bake] {INPUT_EXE} missing — build loader first", file=sys.stderr)
        return 1
    key = run_pack()
    bake_key(key)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
