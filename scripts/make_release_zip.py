"""DeltaHack release packer — plain-shipping (no KFPL wrap).

Just packs loader/build/dh_loader.exe as dist/App.exe inside a ZIP. No
encryption, no key entry, no launcher stub. Site's Play button runs
dist/App.exe with the LAUNCH ARGUMENTS ('run') and everything spins up.

MZ header sanitizer inside dh_loader still fires at startup — the on-disk
file has a valid PE header but the running process has "MZ..PE" wiped from
its own base module. That protection is independent of KFPL.

Usage:
    python scripts/make_release_zip.py [--version 1.0.0]
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
RELEASES = ROOT / "releases"


def run(cmd, cwd=None):
    print(f"[run] {' '.join(cmd)}")
    r = subprocess.run(cmd, cwd=cwd, shell=False)
    if r.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(cmd)}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="1.0.0")
    ap.add_argument("--channel", default="stable")
    ap.add_argument("--no-loader-build", action="store_true",
                    help="Skip loader build; use whatever is at loader/build/dh_loader.exe.")
    args = ap.parse_args()

    if not args.no_loader_build or not LOADER_EXE.exists():
        print("[step] building loader")
        run(["cmd.exe", "/c", str(ROOT / "loader" / "build.bat")],
            cwd=ROOT / "loader")
    if not LOADER_EXE.exists():
        print(f"[!] missing {LOADER_EXE}", file=sys.stderr); return 1

    payload = LOADER_EXE.read_bytes()
    payload_sha = hashlib.sha256(payload).hexdigest()
    print(f"[pack] {LOADER_EXE.name} ({len(payload):,} B, sha256 {payload_sha[:16]}...)")

    stage = ROOT / "release_staging"
    if stage.exists(): shutil.rmtree(stage)
    dist = stage / "dist"
    dist.mkdir(parents=True, exist_ok=True)
    (dist / "App.exe").write_bytes(payload)

    # kdu vulnerable-driver payloads — dh_loader scans <exeDir>\db\*.bin
    db_dst = dist / "db"
    db_dst.mkdir(exist_ok=True)
    db_src = ROOT / "loader" / "src" / "db"
    n_bins = 0
    for p in db_src.glob("*.bin"):
        shutil.copyfile(p, db_dst / p.name)
        n_bins += 1
    print(f"[pack] included {n_bins} driver .bin payloads under dist/db/")

    RELEASES.mkdir(exist_ok=True)
    zip_path = RELEASES / f"DeltaHack-{args.version}.zip"
    if zip_path.exists(): zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for p in dist.rglob("*"):
            if p.is_file():
                z.write(p, p.relative_to(stage))
    shutil.rmtree(stage)

    zip_size = zip_path.stat().st_size

    print()
    print("=" * 72)
    print(f"  READY:  {zip_path}")
    print(f"  Size:   {zip_size:,} bytes ({zip_size/1024/1024:.2f} MB)")
    print()
    print("  Fill on the site's 'Upload release' form:")
    print(f"    VERSION            {args.version}")
    print(f"    CHANNEL            {args.channel}")
    print(f"    PACKAGE            {zip_path.name}   (upload the ZIP)")
    print(f"    LAUNCH EXECUTABLE  dist/App.exe")
    print(f"    LAUNCH ARGUMENTS   run")
    print(f"    CONTENT KEY        (empty)")
    print(f"    LOADER KEY         (empty)")
    print(f"    KFPL KEY           (empty)")
    print(f"    Activate now       ON")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
