"""DeltaHack standalone build — no site, no launcher, just a ZIP.

Contents:
    DeltaHack/
        dh_loader.exe        — the main binary
        db/*.bin             — 23 driver payloads
        START.bat            — self-elevating launcher (double-click)
        README.txt           — one-page instructions

User workflow:
    1. Extract ZIP anywhere (Desktop, C:\, wherever)
    2. Double-click START.bat
    3. UAC prompts → click Yes
    4. Console opens, dh_loader waits for Delta
    5. Launch Delta Force
    6. Overlay appears

Usage (packer side):
    python scripts/make_standalone_zip.py [--version 1.0.5]
"""
from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
LOADER_EXE = ROOT / "loader" / "build" / "dh_loader.exe"
DB_SRC = ROOT / "loader" / "src" / "db"
RELEASES = ROOT / "releases"


START_BAT = r"""@echo off
REM DeltaHack standalone launcher.
REM Self-elevates via PowerShell if not already admin, then runs dh_loader.

setlocal enabledelayedexpansion
cd /d "%~dp0"

REM Check admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [DeltaHack] Requesting administrator rights...
    powershell -Command "Start-Process -FilePath '%~dpnx0' -Verb RunAs -WorkingDirectory '%~dp0'"
    exit /b 0
)

REM We're admin now
echo.
echo   =============================================================
echo   DeltaHack - waiting for Delta Force to launch
echo   =============================================================
echo.
echo   1. Keep this window open
echo   2. Launch Delta Force normally (Steam / desktop shortcut)
echo   3. Overlay will appear over the game
echo   4. Close this window to stop
echo.

dh_loader.exe run
set RC=%errorlevel%

echo.
echo   dh_loader exited with code %RC%
echo   Log: %%LOCALAPPDATA%%\KoenFlowLauncher\logs\dh_loader.log
echo.
pause
"""


README = r"""DeltaHack - Standalone Test Build
==================================

Requires:
  - Windows 11 24H2 (build 26100) or 25H2 (build 26200)
  - Administrator rights (UAC prompt on first launch)
  - Delta Force (Global Steam release)

How to run:
  1. Extract this ZIP anywhere (Desktop is fine)
  2. Double-click START.bat
  3. Click YES on the UAC prompt
  4. Keep the console window open
  5. Launch Delta Force from Steam
  6. Overlay boxes should appear over enemies

Controls (in-game overlay window):
  F1  - Toggle player ESP on/off
  F2  - Toggle bot ESP on/off
  Close console  - Stop overlay + unload driver

Troubleshooting:
  - "Windows build ... is out of scope"
    Only 24H2 / 25H2 supported. Older builds are gated.
  - "SeDebugPrivilege enable failed"
    Not running as admin. Right-click START.bat -> Run as administrator.
  - "ntoskrnl base: 0x0"
    Same reason - not admin.
  - Nothing happens after game launch
    Check log at:
    %LOCALAPPDATA%\KoenFlowLauncher\logs\dh_loader.log

Session isolation note:
  START.bat elevates via UAC in the SAME user session (not Session 0),
  so the overlay window shows on the user's desktop.

Do NOT run the exe directly from an unelevated cmd prompt - kdu driver
load will fail and you'll get an SVC_START error.
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="1.0.5")
    ap.add_argument("--no-loader-build", action="store_true")
    args = ap.parse_args()

    if not args.no_loader_build or not LOADER_EXE.exists():
        print("[step] building loader")
        r = subprocess.run(["cmd.exe", "/c", str(ROOT / "loader" / "build.bat")],
                           cwd=ROOT / "loader")
        if r.returncode != 0:
            print("[!] loader build failed", file=sys.stderr); return 1
    if not LOADER_EXE.exists():
        print(f"[!] missing {LOADER_EXE}", file=sys.stderr); return 1

    payload = LOADER_EXE.read_bytes()
    payload_sha = hashlib.sha256(payload).hexdigest()

    stage = ROOT / "standalone_staging"
    if stage.exists(): shutil.rmtree(stage)
    pkg = stage / "DeltaHack"
    pkg.mkdir(parents=True, exist_ok=True)

    (pkg / "dh_loader.exe").write_bytes(payload)
    (pkg / "START.bat").write_bytes(START_BAT.replace("\n", "\r\n").encode("ascii"))
    (pkg / "README.txt").write_bytes(README.replace("\n", "\r\n").encode("utf-8"))

    db_dst = pkg / "db"
    db_dst.mkdir(exist_ok=True)
    n_bins = 0
    for p in DB_SRC.glob("*.bin"):
        shutil.copyfile(p, db_dst / p.name)
        n_bins += 1
    print(f"[pack] loader ({len(payload):,} B, sha256 {payload_sha[:16]}...) + {n_bins} .bin")

    RELEASES.mkdir(exist_ok=True)
    zip_path = RELEASES / f"DeltaHack-standalone-{args.version}.zip"
    if zip_path.exists(): zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for p in pkg.rglob("*"):
            if p.is_file():
                z.write(p, p.relative_to(stage))
    shutil.rmtree(stage)

    zip_size = zip_path.stat().st_size

    print()
    print("=" * 72)
    print(f"  READY:  {zip_path}")
    print(f"  Size:   {zip_size:,} bytes ({zip_size/1024/1024:.2f} MB)")
    print()
    print("  Send this file to the tester. They:")
    print("    1. Extract the ZIP anywhere")
    print("    2. Double-click START.bat")
    print("    3. Accept UAC")
    print("    4. Launch Delta")
    print("    5. Overlay appears")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
