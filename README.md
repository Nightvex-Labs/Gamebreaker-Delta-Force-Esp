# DeltaHack

External ESP for Delta Force (UE4.24.2 + Tencent ACE). Ships as a single
`WinRuntimeHost.exe` distributed through the KoenFlow launcher.

## Architecture

- **External process** — no injection into the target. Physical memory
  reads via kdu BYOVD shellcode driver.
- **Provider**: `inpoutx64` (REDFOX #26) — WHCP-signed, HVCI-safe.
- **Rendering**: D3D11 + DirectComposition transparent overlay, ImGui HUD,
  `WDA_EXCLUDEFROMCAPTURE` to block OBS / ShadowPlay.
- **Position decrypt**: Unicorn Engine emulates Delta's own `DecVector`
  routine on `FEncVector` payloads (see `docs/DELTA_DECRYPT_ALGORITHM.md`).
- **OS support**: Win10 20H1..22H2 (19041..19045), Win11 21H2..26H2
  (22000..30000) via runtime EPROCESS layout table.

## Repo layout

```
loader/          — main C/C++ source (compiles to WinRuntimeHost.exe)
  src/           — implementation
    main.c              — wmain, arg dispatch (run, daemon-esp, overlay-imgui, dev commands)
    log.c               — persistent file sink → %LOCALAPPDATA%\...\core.log
    dh_mz_wipe.c        — runtime PE-header sanitizer
    dh_item_catalog.c   — item name lookup (16k rows)
    db/                 — kdu payload unpacker
    decrypt/            — ACE decrypt (Unicorn-based, VTBL Feistel, C280, spray)
    hardening/          — AMSI/ETW patches, direct syscalls, auth presence check
    hollow/             — process hollowing (disabled by default, kept for future)
    mem/                — RPM (physical + virtual), EPROCESS walk, FName resolve
    overlay/            — D3D11+DComp+ImGui overlay + daemon-esp reader
    svc/                — SCM install for kdu driver
    winio/              — provider registry + phys R/W dispatch
  inc/           — public headers
  deps/          — third-party (imgui, vmprotect SDK, stb)
  assets/        — overlay assets
  build.bat      — one-shot build (VMProtect linkage via /DDH_VMPROTECT)

launcher/        — legacy KFPL launcher stub (SUPERSEDED — loader.exe is now
                   wrapped directly by VMProtect_Con and ships as WinRuntimeHost.exe)

scripts/         — release packing helpers
docs/            — architecture, decrypt algorithm write-up, status notes
```

## Build

Requires MSVC 14.44 (VS 2022 Community + Win11 SDK 26100) and Unicorn 2.1.4
static libs at `../deps/unicorn/static/`.

```
cd loader
build.bat
# → build\dh_loader.exe
```

Post-build wrap:
```
VMProtect_Con.exe build\dh_loader.exe build\WinRuntimeHost.exe
```

Ship zip = 3 files:
- `WinRuntimeHost.exe` (wrapped)
- `VMProtectSDK64.dll`
- `db/inpoutx64.bin`

## Launch flow (via KoenFlow)

1. Play button → `CreateProcessAsUser(WinRuntimeHost.exe, ...)` elevated.
2. `wmain` → auth presence check (silent exit if no launch-context arg / env token).
3. Default command = `run` → signal `Global\{DHREADY-...}` event immediately.
4. `driver_up` → SCM install kdu → open device → probe IOCTL.
5. `RpmFindSystemCR3` → wait up to 120s for DeltaForceClient-Win64-Shipping.
6. `DaemonEspEnsureShmem` on main thread (so overlay attach can't race).
7. `CreateThread(DaemonEspRun)` — reader thread @ ~200 Hz, decrypts FEncVector,
   publishes to `Global\{7A9F3B21-...}` shmem.
8. `OverlayRunImGui` on main thread — D3D11+DComp overlay, HOME hotkey, F1..F4
   feature toggles.
9. On overlay window close: signal daemon stop, join, driver_down, exit.

## UI

Current overlay UI is ImGui in `loader/src/overlay/dh_overlay_imgui.cpp`.
Panel opens on HOME hotkey (message-only sink window catches `WM_HOTKEY`).
Every feature toggle defaults to `false` at init — silent overlay on install.

**Team task**: replace the ImGui panel with a new UI while keeping the shmem
contract (`inc/dh_shmem.h`) intact — reader thread stays as-is, only the
render path changes.

## Anti-cheat notes

- **ACE (Tencent)** — kernel-callbacks heavy, decoy-EPROCESS filter.
- **Bypass**: external + kdu shellcode + call-through-decrypt (no injection,
  no in-game hooks, no handle to target process).
- **HVCI-safe** — inpoutx64 is WHCP-signed, no manual-map.

See `docs/ARCHITECTURE.md` for the full breakdown.
