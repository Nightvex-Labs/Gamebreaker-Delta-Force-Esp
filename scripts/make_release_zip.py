"""DeltaHack release packer — KFPL wrap + DHBE trailer.

Pipeline:
  1. Build loader (loader/build/dh_loader.exe) — the raw payload.
  2. Bake ZERO KFPL_KEY into launcher (release mode). Fresh random real key
     printed to console — operator pastes it into admin panel.
  3. Build launcher stub (launcher/build/App.exe).
  4. VMProtect wrap launcher stub (Ultra virtualization of resolve_key,
     extract_key_from_launch_context, aes_gcm_decrypt, antitheft_guard).
  5. Append DHBE trailer to wrapped launcher — bundle embedded past PE end.
     Result: single self-contained WinRuntimeHost.exe.
  6. Assemble ZIP: WinRuntimeHost.exe + VMProtectSDK64.dll + db/inpoutx64.bin.

Usage:
    python scripts/make_release_zip.py                # zero-key (release)
    python scripts/make_release_zip.py --bake-real    # dev: bake real key
    python scripts/make_release_zip.py --skip-loader  # reuse existing dh_loader.exe
"""
from __future__ import annotations

import argparse
import hashlib
import shutil
import struct
import subprocess
import sys
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
LOADER_DIR = ROOT / "loader"
LOADER_EXE = LOADER_DIR / "build" / "dh_loader.exe"
LAUNCHER_DIR = ROOT / "launcher"
LAUNCHER_EXE = LAUNCHER_DIR / "build" / "App.exe"
BUNDLE_KFPL = LAUNCHER_DIR / "embed" / "dh_loader.kfpl"
DB_DIR = LOADER_DIR / "src" / "db"
VMP_SDK_DLL = LOADER_DIR / "deps" / "vmprotect" / "lib" / "VMProtectSDK64.dll"
VMP_CON = Path(r"C:\DeltaHack\tools\vmprotect\notVmp\VMProtect_Con.exe")
RELEASE = ROOT / "release"


def run(cmd, cwd=None):
    print(f"[run] {' '.join(str(c) for c in cmd)}")
    r = subprocess.run(cmd, cwd=cwd, shell=False)
    if r.returncode != 0:
        raise RuntimeError(f"command failed rc={r.returncode}: {' '.join(str(c) for c in cmd)}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bake-real", action="store_true",
                    help="dev only: bake real key into launcher source")
    ap.add_argument("--skip-loader", action="store_true",
                    help="reuse existing loader/build/dh_loader.exe")
    args = ap.parse_args()

    # ── 1. Build loader (payload) ─────────────────────────────────────────
    if not args.skip_loader or not LOADER_EXE.exists():
        print("[step] building loader payload -> dh_loader.exe")
        run(["cmd.exe", "/c", str(LOADER_DIR / "build.bat")], cwd=LOADER_DIR)
    if not LOADER_EXE.exists():
        print(f"[!] missing {LOADER_EXE}", file=sys.stderr); return 1
    print(f"[pack] loader payload: {LOADER_EXE.stat().st_size:,} B")

    # ── 2. Pack KFPL + bake key ───────────────────────────────────────────
    if args.bake_real:
        print("[step] KFPL wrap + BAKE real key (dev/local — key leaks with binary)")
        run([sys.executable, str(LAUNCHER_DIR / "bake.py"), "--bake"], cwd=LAUNCHER_DIR)
    else:
        print("[step] KFPL wrap — ZERO-key (release, env/context-injected required)")
        run([sys.executable, str(LAUNCHER_DIR / "bake.py")], cwd=LAUNCHER_DIR)
    if not BUNDLE_KFPL.exists():
        print(f"[!] missing {BUNDLE_KFPL}", file=sys.stderr); return 1

    # ── 3. Build launcher stub ────────────────────────────────────────────
    print("[step] building launcher stub -> App.exe")
    run(["cmd.exe", "/c", str(LAUNCHER_DIR / "build.bat")], cwd=LAUNCHER_DIR)
    if not LAUNCHER_EXE.exists():
        print(f"[!] missing {LAUNCHER_EXE}", file=sys.stderr); return 2

    # ── 4. VMProtect wrap launcher ────────────────────────────────────────
    print("[step] VMProtect wrap App.exe -> App.vmp.exe")
    wrapped = LAUNCHER_EXE.parent / "App.vmp.exe"
    if wrapped.exists(): wrapped.unlink()
    if not VMP_CON.exists():
        print(f"[!] VMProtect_Con.exe not found at {VMP_CON}", file=sys.stderr); return 3
    run([str(VMP_CON), str(LAUNCHER_EXE), str(wrapped)])
    if not wrapped.exists():
        print(f"[!] VMProtect wrap failed — no output at {wrapped}", file=sys.stderr); return 3
    print(f"[pack] wrapped launcher: {wrapped.stat().st_size:,} B")

    # ── 5. Append DHBE trailer (self-embedded bundle) ─────────────────────
    # Trailer format at end of file:
    #   [ bundle bytes (N) ][ u64 LE bundle_size ][ 4-byte magic "DHBE" ]
    stub_bytes   = wrapped.read_bytes()
    bundle_bytes = BUNDLE_KFPL.read_bytes()
    trailer      = struct.pack("<Q", len(bundle_bytes)) + b"DHBE"
    RELEASE.mkdir(parents=True, exist_ok=True)
    stage_exe = RELEASE / "WinRuntimeHost.exe"
    with open(stage_exe, "wb") as f:
        f.write(stub_bytes)
        f.write(bundle_bytes)
        f.write(trailer)
    print(f"[pack] embedded bundle into WinRuntimeHost.exe "
          f"(stub={len(stub_bytes):,} + bundle={len(bundle_bytes):,} + trailer=12 = "
          f"{stage_exe.stat().st_size:,} B)")

    # ── 6. Ship zip ───────────────────────────────────────────────────────
    zip_path = RELEASE / "WinRuntimeHost.zip"
    if zip_path.exists():
        import datetime as _dt
        stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = RELEASE / f"WinRuntimeHost_prev_{stamp}.zip"
        zip_path.rename(backup)
        print(f"[pack] backed up previous zip -> {backup.name}")

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(stage_exe, "WinRuntimeHost.exe")
        z.write(VMP_SDK_DLL, "VMProtectSDK64.dll")
        n_bins = 0
        for p in sorted(DB_DIR.glob("*.bin")):
            z.write(p, f"db/{p.name}")
            n_bins += 1
        print(f"[pack] included {n_bins} driver .bin under db/")

    zsz = zip_path.stat().st_size
    zsha = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    print()
    print("=" * 72)
    print(f"  SHIP: {zip_path}")
    print(f"    size:   {zsz:,} B")
    print(f"    sha256: {zsha}")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
