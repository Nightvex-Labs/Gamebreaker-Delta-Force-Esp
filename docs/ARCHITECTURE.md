# DeltaHack — Как это работает

Внешний ESP для Delta Force (UE4.24.2 + Tencent ACE). Ни строчки нашего
кода не запускается внутри Delta или ACE — вся работа через kdu BYOVD
драйвер в ring 0, читаем physical memory, транслируем в virtual через CR3,
пишем в shared memory, овер­лей на транспарентном D3D11-окне.

---

## Общий поток

```
┌──────────────────────────────────────────────────────────────────┐
│  SESSION 0 — SYSTEM (dh_loader.exe daemon-esp)                   │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ 1. Загрузка kdu провайдера                              │    │
│  │    dh_prov_registry.c → выбор по priority (inpoutx64=1000)│  │
│  │    dh_prov_impl.c    → SCM install → CreateFile         │    │
│  │    dh_provider.h     → { DhProviderPhysRead/Write }     │    │
│  └─────────────────────────────────────────────────────────┘    │
│                            │                                     │
│                            ▼                                     │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ 2. Kernel discovery (dh_rpm.c)                          │    │
│  │    - ntoskrnl base via ZwQuerySystemInformation         │    │
│  │    - PsInitialSystemProcess ptr                         │    │
│  │    - Walk EPROCESS.ActiveProcessLinks                   │    │
│  │    - Match "DeltaForceClientR" → capture CR3            │    │
│  │    - EPROCESS+0x2E0 → PEB → ImageBase                   │    │
│  └─────────────────────────────────────────────────────────┘    │
│                            │                                     │
│                            ▼                                     │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ 3. Main tick loop (poll_and_publish, 120Hz cap)         │    │
│  │    a. GWorld @ base+0x1DA98608                          │    │
│  │    b. UWorld+0x140 = GameState (encrypted ptr, mask 48b)│    │
│  │    c. GS+0x388     = PlayerArray TArray<PS*>            │    │
│  │    d. Loop PS[i]:                                       │    │
│  │       - PS.PawnPrivate  (@ +0x3F8)                      │    │
│  │       - PS.TeamID       (@ +0x660)                      │    │
│  │       - PS.bDead        (@ +0x4B4)                      │    │
│  │       - pawn.RootComp   (@ +0x180)                      │    │
│  │       - root.RelativeLocation (@ +0x168) = FEncVector   │    │
│  │       - if Index=0xFFFF → plaintext (это МЫ)            │    │
│  │       - else → DECRYPT цикл (см. ниже)                  │    │
│  │    e. Bot Phase A (60Hz gate):                          │    │
│  │       - re-RPM known bot pawns at pawn+0x1D10 (plain)   │    │
│  │       - last-known cache для skip-tick'ов               │    │
│  │    f. Bot Phase B (4Hz):                                │    │
│  │       - Walk UWorld.PersistentLevel.Actors[0..2048]     │    │
│  │       - filter sanity + dedupe с players → s_bot_pawns  │    │
│  │    g. Publish под primary seqlock:                      │    │
│  │       shmem->sequence++ (odd) → count/team/players[]    │    │
│  │       shmem->sequence++ (even)                          │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ 4. Cam thread (120Hz, dedicated, ABOVE_NORMAL priority) │    │
│  │    ОДИН batch 32B RPM @ pcm+0x31DB0:                    │    │
│  │      +0x00 FEncVector Location (16B)                    │    │
│  │      +0x10 FRotator   Rotation (12B, pitch/yaw/roll)    │    │
│  │      +0x1C float      FOV                                │    │
│  │    Fallback: ctrl+0x380 ControlRotation                 │    │
│  │    Publish под cam_seq (независимый seqlock):           │    │
│  │      shmem->cam_seq++ (odd) → myX/Y/Z/yaw/pitch/roll/fov│    │
│  │      shmem->cam_seq++ (even)                            │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  Обе публикуют в:                                                │
│  Global\DeltaHackEsp — CreateFileMapping SD "Everyone GA"        │
└──────────────────────────────────────────────────────────────────┘
                             │
                             │ shared memory (page-backed)
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│  SESSION 1 — USER (dh_loader.exe overlay)                        │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ Poll thread (500Hz, Sleep(2))                            │    │
│  │   1. Entity block под sequence lock (8 retries)         │    │
│  │      → count + players[]                                 │    │
│  │   2. Cam block под cam_seq lock (8 retries)             │    │
│  │      → cam.pos + rot + fov                               │    │
│  │   Оба lock'а независимы — медленный entity walker       │    │
│  │   не может застопорить cam poll.                        │    │
│  └─────────────────────────────────────────────────────────┘    │
│                            │                                     │
│                            ▼                                     │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ Render loop (D3D11 + DComp, ≤240Hz, VSync-capped)       │    │
│  │   - Client-side prediction:                              │    │
│  │     e.x += e.vx * min(GetTickCount64() - e.pos_ts_ms, 200ms) / 1000 │
│  │   - W2S (ABI Hor+ rotation matrix из yaw/pitch/roll)    │    │
│  │   - Boxes (пелвис-центрированные)                       │    │
│  │   - Names + team color (PLAYERS цветные, BOTS белые)    │    │
│  │   - Skeleton lines                                       │    │
│  │   - Radar (top-right)                                    │    │
│  │   - Distance chip                                        │    │
│  │   - Hotkeys: F1 = Players toggle, F2 = Bots toggle      │    │
│  └─────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
```

---

## Decrypt (сердце проекта)

Delta шифрует `LastFrameWorldPosition` (pawn+0x1D10) — 16-байтная
`FEncVector` = `{ float X, Y, Z; struct EncHandler { u16 Index; ... }; }`.

### Cipher: Feistel-20
- 20 раундов, MAGIC constant `0x2E2AC781`, TEA-style delta `0x61C88647`
- Native call target — вызов через vtable slot 6 объекта по `*0x15CEDA120`
- Все реализовано в 571-байтном bare-metal shellcode

### Key derivation
Для расшифровки нужен per-entity key. Delta хранит его в дереве по индексу:
1. `LOOKUP+0x278` → `key_obj` (ptr меняется каждый тик — dynamic!)
2. Идём по linked list, XOR/ror64/sub цепочке, пока не найдём node с
   Handler.Index == нашему
3. Вытаскиваем 8-байтный ключ из этого node

Реализация — `dh_derive_key.c`. Полный dispatch + cipher формула
описаны в `DELTA_DECRYPT_ALGORITHM.md`.

### Как мы это дёргаем внешне
- RPM-читаем chunks Delta .text вокруг `0x143246120` (`FENCVEC_IMPL`)
- Копируем в наш VirtualAlloc(RWX) буфер
- Patch rel32 переходов (обертка вокруг чужих call'ов)
- Локальный `CALL` через MASM wrapper `CallVtblDecryptSpray`
- Zero-injection — код Delta исполняется в НАШЕМ процессе

Bot'ы (`AI_*`) не шифруются — их позиция plaintext в том же слоте.

---

## Provider layer (HVCI-friendly)

Раньше жёстко висели на EneIo64 (kdu #6). Под HVCI EneIo64 блокируется
Microsoft Vulnerable Driver Blocklist (error `0x800B010C` = `TRUST_E_NOSIGNATURE`).

Пересобрали в multi-provider:
```
dh_provider.h        — API (DhProviderSelect, DhProviderPhysRead/Write)
dh_prov_registry.c   — 21 драйвер с { kdu_id, protocol, IOCTL codes, priority }
dh_prov_impl.c       — handlers per-protocol:
                       WINIO_REQ (16B):  EneIo64 family, MsIo64, HwRwDrv...
                       REDFOX_REQ (32B): inpoutx64 { SectionHandle, ViewSize,
                                                     BusAddress, BaseAddress }
                       UCOREW_REQ:       AsIO3, ucore-family
                       ASUSIO:           AsusIO
dh_phys.c            — dispatcher: g_active_provider ? provider : legacy
```

### Priority (текущий)
```
inpoutx64  1000  REDFOX   ← primary, HVCI-safe
EneIo64    200   WINIO    ← HVCI-off fallback (previous default)
AsIO3      150   UCOREW   ← HVCI-safe
... 18 others
```

Selection algorithm: пробуем по убыванию priority, первый который:
(1) грузится, (2) открывает DeviceObject — становится активным. Fast-path:
если device уже existent (previous run daemon'а), reuse без SCM install.

### Правила
- **НИКОГДА не IOCTL к незнакомому драйверу** (feedback_never_ioctl_unknown_driver) — BSOD risk. Провайдеры валидируются против kdu source.
- Smoke test через реальный IOCTL УДАЛЁН — только SCM start + CreateFile проверяют работоспособность.

---

## Файловая структура (build-relevant)

```
loader/inc/
  dh_common.h        — u32/u64/i32 typedefs, DH_ERR_* codes, DH_INFO/WARN/ERROR macros
  dh_provider.h      — provider API
  dh_rpm.h           — RPM primitives + FName resolver
  dh_phys.h          — Physical R/W
  dh_dbunpack.h      — kdu DBPACK decoder
  dh_scm.h           — SCM helpers
  dh_ace_decrypt.h   — legacy XORPS decrypt (secondary path)
  dh_derive_key.h    — DeriveKey API
  dh_spray.h         — RWX spray helpers
  dh_state_cache.h   — decrypt state cache
  dh_unicorn_decrypt.h — Unicorn emu fallback API
  dh_shared.h        — shared constants
  dh_shmem.h         — DH_SHMEM struct + DH_CAM_CACHE + magic/name

loader/src/
  main.c                  — CLI dispatch (daemon-esp, overlay, esp, probe-*, ...)
  log.c                   — timestamped logger (DH_INFO/WARN/ERROR)
  db/dh_dbunpack.c        — DBPACK unpack for kdu embedded drivers
  db/*.bin                — 20 vulnerable driver payloads
  svc/dh_scm.c            — service install/start/stop/delete
  winio/dh_phys.c         — PhysRead/Write dispatch
  winio/dh_prov_registry.c — 21 provider metadata
  winio/dh_prov_impl.c    — per-protocol IOCTL handlers
  mem/dh_rpm.c            — Virtual RPM (CR3 walk, phys mapping)
  decrypt/dh_vtbl_decrypt.c — VTBL_DECRYPT_120 shellcode host
  decrypt/dh_derive_key.c   — DeriveKey linked-list walker
  decrypt/dh_spray.c        — RWX + rel32 patcher
  decrypt/dh_ace_decrypt.c  — legacy XORPS decrypt path
  decrypt/dh_c280_decrypt.c — alt dispatch variants
  decrypt/dh_unicorn_decrypt.c — Unicorn fallback (когда shellcode fails)
  decrypt/dh_state_cache.c    — decrypt state persistence
  decrypt/vtbl_call_wrap.asm  — MASM: pass FEncVector by xmm1
  decrypt/vtbl_spray_wrap.asm — MASM: spray-safe wrapper
  overlay/dh_daemon_esp.c     — SYSTEM daemon (см. поток выше)
  overlay/dh_overlay.cpp      — Session 1 D3D11 overlay + ImGui-lite HUD
```

---

## Deploy pipeline

**Разработка:** PC1 (23H2)
**Тесты:** 2PC (Ryzen 7500F, 25H2, HVCI ON), 192.168.31.250

```
PC1: build.bat → loader/build/dh_loader.exe (27 MB, single-binary)
      ↓ scp через C:\DeltaHack\tools\ssh\
2PC: C:\DeltaHack\loader\build\dh_loader.exe
      ↓ schtasks scheduled tasks:
      \DeltaHack-Autostart    (boot → SSH firewall + BSOD dump collector)
      \DeltaHackTest          (daemon-esp в Session 0, SYSTEM)
      \DeltaHackOverlay       (overlay в Session 1, user)
```

Ручной запуск daemon-esp = admin CMD:
```
dh_loader.exe daemon-esp > daemon.log 2>&1
```

Overlay = обычный пользователь:
```
dh_loader.exe overlay
```

Оба общаются только через `Global\DeltaHackEsp`.

---

## Что декомпозирует Byte-подход

- **Никакой инъекции в Delta.** ACE не может seans'нуть чужой процесс.
- **Никакого DMA.** Хардварная нейтральность — работаем на любом рабочем железе с HVCI.
- **Никакого IOCTL по догадкам.** Каждый провайдер — валидированный kdu source.
- **Никаких stub'ов в коде.** Всё что не работает — вырезано или явно помечено как secondary/fallback.
- **Никаких live-scanner'ов в prod'е.** Всё offset discovery — оффлайн, per-sig AOB или Dumper-7 output.
