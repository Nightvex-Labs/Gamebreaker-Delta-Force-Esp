# DeltaHack — статус проекта

**Дата отчёта:** 2026-09-20
**Ветка:** external process + kdu BYOVD (без DMA, без внутренней инъекции)
**Целевой билд Delta:** `1.102.37117.80` SVN `7689207` (2026-08-29, Ma4Release Global Steam)
**Целевая среда:** Windows 11 24H2 / 25H2, HVCI ON, Hyper-V ON, Secure Boot ON, Intel+AMD

---

## Что работает

### Инфраструктура (Ring 0 comms)
- **kdu BYOVD** — 21 драйвер зарегистрирован в `dh_prov_registry.c`, primary = `inpoutx64` (kdu #26, REDFOX-protocol, WHCP-signed, проходит Microsoft Vulnerable Driver Blocklist под HVCI)
- **Провайдер-абстракция** — `dh_provider.h` + `dh_prov_impl.c` умеет WINIO / ASUSIO / UCOREW / REDFOX семейства IOCTL, автоселект по приоритету, fast-path переиспользования уже установленного драйвера
- **Physical R/W** — `dh_phys.c` дёргает `g_active_provider` или падает в legacy EneIo64 хардкод
- **Virtual RPM** — `dh_rpm.c` полный pipeline: SysCR3 → EPROCESS enum → PsInitialSystemProcess → target CR3 → PEB → ImageBase
- **HVCI-совместимость проверена** — 2PC Ryzen 7500F Win11 25H2 с включёнными HVCI / VBS / Hyper-V / Secure Boot: pipeline поднимается, RPM работает

### Decrypt (Delta position cipher)
- **VTBL_DECRYPT_120 shellcode** (Feistel-20, MAGIC=`0x2E2AC781`, TEA-delta=`0x61C88647`) — обратно инжинирован из Delta @ `0x143246120`, экспортирован в 571 байт zero-deps machine code, локальный RWX-копия + вызов через MASM wrapper
- **DeriveKey** — walk по linked list @ `LOOKUP+0x278`, вычисляет per-Handler.Index key — реализовано в `dh_derive_key.c`
- **Live decrypt в рейде** — position decrypt работает на всех T1-T5 игроках, ~90%+ success rate на тик, fallback cache 500ms между успешными декриптами
- **AI боты не шифруются** — их позиции читаем plaintext из `pawn+0x1D10` (`LastFrameWorldPosition FEncVector`)

### ESP (внешний overlay)
- **D3D11 + DComp overlay** — прозрачное WS_LAYERED+WS_TRANSPARENT+WS_TOPMOST окно
- **Рендер** — боксы (пелвис-центрированные, feet_y=sy+bh/2, head_y=sy-bh/2), имена, скелет, радар, дистанция
- **Bot detection + white color** — все `AI_*` рендерятся белым (радар + мир)
- **Hotkey toggles** — F1 = Players ESP on/off, F2 = Bots ESP on/off, состояние в top-bar
- **W2S** — ABI-verified Hor+ rotation matrix из POV yaw/pitch/roll

### IPC (daemon ↔ overlay)
- **Global\DeltaHackEsp** — named shared memory, `DH_SHMEM_MAGIC=0xDECAF0DE`, 64 слота
- **Двойной seqlock** —
  - `sequence` для entity block (count + players[])
  - `cam_seq` для camera block (myX/Y/Z + yaw/pitch/roll + fov) — независимый lock
- **Cam thread** — dedicated 120Hz поток в daemon, один batch 32B RPM за тик (POV.Location+Rot+FOV), THREAD_PRIORITY_ABOVE_NORMAL
- **Bot Phase A** — 60Hz gate (16ms) + last-known cache чтобы боты не мигали между рефрешами
- **Bot Phase B** — 4Hz полный rescan UWorld.PersistentLevel.Actors[0..2048]
- **Client-side prediction** — pos_ts_ms + vx/vy/vz per-pawn velocity tracker, extrapolation до 200ms

### Deploy на 2PC
- **Autostart** через scheduled tasks: `\DeltaHack-Autostart`, `\DeltaHackTest` (daemon-esp), `\DeltaHackOverlay`
- **SSH** — `192.168.31.250` → C:\DeltaHack\tools\ssh\ с key auth
- **BSOD recovery** — autostart.bat собирает latest minidump + пишет в C:\DeltaHack\logs\autostart.log

---

## Что открыто / нестабильно

1. **procCR3 regression после Delta relaunch** (2026-09-19)
   Иногда procCR3 не транслирует user VAs после перезапуска игры — нужен reset SysCR3 walk

2. **Ghost boxes** — иногда рендерятся боксы там где ничего нет
   Причины (по приоритету):
   - stale pawn ptr в s_pscache[] (до 1000ms TTL)
   - position cache holdover (s_poscache[idx] до 500ms TTL)
   - слишком лояльный sanity (|x,y|<200k, |z|<20k)

3. **Flicker** — короткие blink'и на противниках
   - REDFOX map/unmap fail при высокой частоте IOCTL
   - shmem seqlock retry исчерпывается (8 iter теперь vs 4 ранее)
   - key_obj реаллокация mid-derive

4. **Decrypt garbage через sanity** — редкие всплывающие координаты типа 1.7e24 (наблюдалось на "ShyistR" в свежем логе). Sanity должен резать NaN + магнитуды, но одиночные баг-декрипты проскакивают

5. **Camera lag при резком дёргании мыши** — cam thread 120Hz даёт ~8ms stale, но враг-позиция всё ещё 19ms stale → визуальный дизматч на быстрых поворотах. Fix: второй dedicated thread для decrypt'а known-пав'ов той же формы как cam thread

6. **Player cap 32** в daemon output (log показывает `players=32/33`), хотя `DH_MAX_PLAYERS=64` — надо проверить где cap реально стоит

7. **DumperDelta.dll** — рабочая копия сохранена, но source в `abi_delta_dumper` для старого билда Delta и падает в `InitEngineCore`. Нужен свежий port на 2026-08-29 layout

---

## Что не сделано (roadmap)

### Ближайшее
- [ ] Enemy decrypt thread — dedicated 120Hz поток параллельно cam thread, только decrypt позиций known-пав'ов
- [ ] Pawn vtable validation — верифицировать pawn+0x0 vs known SGCharacter vt на каждом тике, инвалидировать s_pscache при mismatch → убивает ghost boxes
- [ ] Position cache TTL 500ms → 100ms
- [ ] Sanity магнитуды — inject-check <500u/tick (impossible teleport)
- [ ] Handler.Index → PS ptr binding для poscache (уник против collision)

### UI (отложено пользователем на "завтра")
- [ ] ABI-style Nightvex overlay — либо full ImGui+DX11 port control_panel.cpp (~6-8h), либо style-match: D2D + bracket-corner боксы + HP bar + distance color + палитра (~1-2h)
- [ ] Settings: Player/Bots toggles + on/off checkboxes (пока только F1/F2 hotkey)

### Ретро
- [ ] Delete obsolete `payload/` (task #27) — старый вариант internal cheat
- [ ] Delete `overlay/`, `esp/` — старые отдельные проекты, заменены на `loader/src/overlay/`
- [ ] Port pmxdrv64 IOCTL (Intel PMX уникальный protocol) в prov_impl
- [ ] Port AsIO3 pre-open (zombie process trick)

### Опсек / distr (когда будем шипить широко)
- [ ] HWID auth loader
- [ ] Crypter + VMProtect wrap на dh_loader.exe
- [ ] Kernel-side handle hiding
- [ ] PPID spoof для daemon-esp
- [ ] Log scrub (`C:\DeltaHack\logs\*` перед раздачей)

---

## Файловая карта — что живое, что мусор

### Активно используется (в `loader/build.bat`)
```
loader/src/main.c
loader/src/log.c
loader/src/db/dh_dbunpack.c          — DBPACK decoder для kdu payloads
loader/src/svc/dh_scm.c              — SCM install/start/delete
loader/src/winio/dh_phys.c           — Physical R/W dispatch
loader/src/winio/dh_prov_registry.c  — 21 kdu провайдер
loader/src/winio/dh_prov_impl.c      — WINIO/REDFOX/ASUSIO/UCOREW handlers
loader/src/mem/dh_rpm.c              — Virtual RPM (CR3 walk + phys chunk)
loader/src/decrypt/dh_ace_decrypt.c  — legacy ACE decrypt (secondary)
loader/src/decrypt/dh_vtbl_decrypt.c — VTBL_DECRYPT_120 shellcode loader
loader/src/decrypt/dh_c280_decrypt.c — c280 dispatch варианты
loader/src/decrypt/dh_unicorn_decrypt.c — Unicorn emu fallback
loader/src/decrypt/dh_state_cache.c  — key/state cache
loader/src/decrypt/dh_spray.c        — RWX spray + patch rel32
loader/src/decrypt/dh_derive_key.c   — DeriveKey (linked list walk)
loader/src/decrypt/vtbl_call_wrap.asm
loader/src/decrypt/vtbl_spray_wrap.asm
loader/src/overlay/dh_overlay.cpp    — D3D11 overlay (Session 1)
loader/src/overlay/dh_daemon_esp.c   — SYSTEM daemon (Session 0)
```

### Assets (kdu payloads)
```
loader/src/db/*.bin  — 20 vulnerable driver DBPACK blobs
```

### Deprecated / cleanup candidates
```
loader/src/overlay/dh_daemon_esp.c.backup_20260920_065253  — pre-cam-thread backup, УДАЛИТЬ
loader/build/dh_loader.exe.backup_20260920_065253          — pre-cam-thread exe, УДАЛИТЬ
loader/build/overlay_test.log                              — one-shot log, УДАЛИТЬ
inner_fn_output.txt (root)                                 — из ранней RE-сессии, УДАЛИТЬ

payload/                                                   — старый internal вариант, УДАЛИТЬ (task #27)
overlay/ (root)                                            — старый standalone overlay, УДАЛИТЬ
esp/                                                       — старый standalone esp, УДАЛИТЬ
decrypt_test/                                              — one-shot injection test, УДАЛИТЬ
```

### Ref / docs
```
docs/                — spec docs
re/                  — RE findings (night sessions decrypt reversing)
sdk/                 — GOLDEN_OFFSETS.md + Dumper-7 output
kdu/                 — vendored kdu source
DELTA_DECRYPT_ALGORITHM.md — cipher spec для dumper integration
ARCHITECTURE.md      — how it works (см. рядом)
STATUS.md            — этот файл
```

Устаревшие root-level md перемещены в `docs/attic/`:
- `HANDOFF.md`, `SESSION_SUMMARY_2026_09_19.md`, `HVCI_DRIVER_REFACTOR_PLAN.md`, `CURRENT_STATE_2026_09_20_HVCI.md`
