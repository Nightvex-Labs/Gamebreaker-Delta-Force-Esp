================================================================================
  DeltaHack — техническая документация
  Target: Delta Force (UE 4.24.2 + ACE anti-cheat)
  Architecture: external + kdu BYOVD (Bring Your Own Vulnerable Driver)
  Platform: Windows 11 21H2 / 22H2 / 23H2 / 24H2 / 25H2 x64
================================================================================


0. КРАТКО
─────────
DeltaHack — external ESP-читер для Delta Force. Работает вне процесса игры,
читает память Delta через kernel primitive (kdu shellcode инжектится через
уязвимый подписанный драйвер EneIo64/inpoutx64), рендерит ESP в отдельном
transparent overlay-окне (ImGui + D3D11 + DirectComposition).

Ключевые свойства:
  - Zero-инъекция в игровой процесс (совсем)
  - HVCI/VBS-friendly (kdu type-2 shellcode)
  - Anti-detect стек: VMProtect, hashed imports, direct syscalls,
    AMSI/ETW blind, PDB strip, per-build unique SHA256, WDA_EXCLUDECAPTURE
  - Ship-hygiene: cage-move + janitor self-delete, все toggles OFF by default
  - KFPL AES-256-GCM обёртка payload'а + integration с KoenFlow launcher


1. ФИЗИЧЕСКАЯ РАСКЛАДКА ФАЙЛОВ
─────────────────────────────
Финальный shipped .zip (WinRuntimeHost.zip, ~30 MB):

  WinRuntimeHost.exe   — VMP-обёрнутый launcher (bootstrap stub), C, ~14 MB
  bundle.kfpl          — AES-256-GCM зашифрованный dh_loader.exe, ~19 MB
  db/inpoutx64.bin     — VMP-обёрнутый уязвимый драйвер (ENE tech, WHCP-signed)

Раскрывается лаунчером KoenFlow в:
  %LOCALAPPDATA%\KoenFlowLauncher\products\deltaforce\current\

Runtime cage (создаётся при запуске, wipe после закрытия):
  %LOCALAPPDATA%\Microsoft\Windows\SystemCache\{GUID}\


2. ПРОЦЕССНАЯ ИЕРАРХИЯ
──────────────────────
При клике "Launch" в лаунчере KoenFlow:

  NightvexLauncher.exe (лаунчер KoenFlow)
    └─ WinRuntimeHost.exe (original, launcher-cache)   [~200 ms lifespan]
       │  Задача: cage-move → respawn → exit
       │
       └─ WinRuntimeHost.exe (cage-copy, DH_CAGE=1)    [~500 ms lifespan]
          │  Задача: спавн детей + janitor → exit
          │
          ├─ WinRuntimeHost.exe daemon-esp             [лайф до Delta close]
          │    │  Расшифровывает bundle.kfpl → %TEMP%\<random>.exe (dh_loader)
          │    │  Спавнит его с аргументом "daemon-esp"
          │    │
          │    └─ dh_loader.exe daemon-esp             [фактический daemon]
          │         - Bringup kdu через inpoutx64
          │         - RPM цикл 100 Hz
          │         - Публикует ESP-данные в shmem
          │         - Ready event → лаунчер видит "Запущено"
          │         - Health check Delta 500 ms, 3 miss = SetEvent(stop)
          │
          ├─ WinRuntimeHost.exe overlay-imgui          [лайф до stop event]
          │    │  Аналогично распаковывает bundle.kfpl → %TEMP%\<random>.exe
          │    │  Спавнит с аргументом "overlay-imgui"
          │    │
          │    └─ dh_loader.exe overlay-imgui          [overlay UI]
          │         - Читает shmem
          │         - Рендерит D3D11 transparent layered window
          │         - Ждёт stop event → exit
          │
          └─ cmd.exe janitor.bat                       [ждёт всех детей]
             - Ждёт пока WinRuntimeHost.exe нет в tasklist
             - rmdir /s /q <cage>
             - rmdir /s /q <launcher_cache>
             - del %~f0


3. KERNEL PRIMITIVE (kdu + inpoutx64)
─────────────────────────────────────
Uses "Kernel Driver Utility" (kdu) технику от hfiref0x — эксплойт arbitrary
kernel R/W через WHCP-подписанный уязвимый драйвер:

Провайдер #26 (EneIo64 / inpoutx64):
  - Драйвер ENE Technology, подписан Microsoft WHCP
  - HVCI/VBS-совместим (не блокируется по DriverBlocklist по состоянию 2026)
  - Uses IOCTL_ENEIO64_MMU_READ / IOCTL_ENEIO64_MMU_WRITE
    → arbitrary physical memory R/W
  - Shellcode NOT injected в kernel memory, только IOCTL-based transport

Bringup pipeline (dh_loader.exe):
  1. Копирует db/inpoutx64.bin в %TEMP%\<random>.sys
  2. SCM: CreateService (SERVICE_KERNEL_DRIVER) + StartService
     - Retry loop на ERROR_SERVICE_MARKED_FOR_DELETE
  3. CreateFileW(\\.\WinIo) → device handle
  4. Первым делом брутом ищет System EPROCESS (PID=4) через phys sweep:
     - Реад физ памяти чанками
     - Signature scan на EPROCESS сигнатуру
     - Extract DirectoryTableBase → sysCR3
  5. sysCR3 = the master page table, теперь можем translate любой VA
  6. С этого момента: RPM = phys-read через CR3 walk


4. RPM (Remote Memory Read) PIPELINE
────────────────────────────────────
Каждое чтение памяти Delta = виртуальный адрес → физический → IOCTL_READ.

VA → PA translation через 4-level x64 paging:
  PML4[VA[47:39]] → PDPT[VA[38:30]] → PD[VA[29:21]] → PT[VA[20:12]]
  Каждый уровень читаем IOCTL_ENEIO64_MMU_READ (по физ адресу таблицы).
  Финальный PA = PT_entry.frame << 12 | VA[11:0]

Delta process discovery:
  1. Начиная с sysCR3, walk ActiveProcessLinks (EPROCESS-linked list)
  2. Match ImageFileName == "DeltaForceCl" (первые 15 chars)
  3. Grab procCR3 (DTB target-процесса)

EPROCESS layout table (компилируется в код):
  Cobalt (Win11 21H2/22H2/23H2) — DTB=0x28, PID=0x440, LINKS=0x448,
                                  IMGNAME=0x5A8, PEB=0x550
  Germanium (Win11 24H2/25H2)   — DTB=0x28, PID=0x1D0, LINKS=0x1D8,
                                  IMGNAME=0x338, PEB=0x550
  Layout probe при загрузке валидирует что оффсеты корректны.

После получения procCR3 читаем PEB → ImageBase → игровой .text/.data сегмент.


5. ACE ANTI-CHEAT BYPASS
────────────────────────
ACE (Tencent Anti-Cheat) — ring-0 драйвер + userland SGuard64.exe.
Наш bypass:

  a) Полностью external — ACE не видит нас через PsSetCreateProcess/
     ObRegisterCallbacks потому что мы не открываем handle к Delta через
     NtOpenProcess. Читаем память phys-lvl через kdu.

  b) Position decryption:
     - Enemy positions зашифрованы в LastFrameWorldPosition @+0x1D10
     - Formula: pure Feistel, 20 rounds, MAGIC=0x2E2AC781, TEA-delta=0x61C88647
     - Ключ dynamic per-frame (key_obj chain через LOOKUP_TABLE @0x15E111AC0)
     - Fallback hardcoded key = 0x2537 (для non-relevance-group entities)
     - См. dh_ace_decrypt.c + GOLDEN_OFFSETS.md

  c) Class filtering:
     - RPM 10 UClass VAs при boot (APickupBase, AWeaponBase, etc.)
     - Ancestor-фильтр по mgn (metadata generation number) вместо VTable-match
     - Cut loot false-positives 181 → 4-7 per raid

  d) FName resolve (crackal 2026-09-22):
     - block/slot split 14/18 bit
     - case 8 XOR const=0x0C
     - wide-decrypt only на even indices


6. OVERLAY ARCHITECTURE
───────────────────────
Отдельный процесс dh_loader.exe overlay-imgui (не same-process с daemon):
  - Читает shmem `Global\{7A9F3B21-4E2D-4B12-A5F7-8D6E4C9F1B3A}`
  - IPC channel = 4 KB struct с player positions/HP/status
  - Rendering pipeline:
    * CreateWindowExW(WS_EX_TRANSPARENT|WS_EX_LAYERED|WS_EX_TOPMOST|WS_EX_NOACTIVATE)
    * D3D11 device + swap chain
    * DirectComposition для click-through transparent
    * SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)
      → блокирует OBS/ShadowPlay/Discord скриншоты
    * ImGui для ESP boxes/HP bars/status text

  - Runtime toggles (main.c + dh_overlay_imgui.cpp):
    * show_boxes / show_hp / show_bones / show_corpses / show_distance
    * show_bot_* separated от show_player_*
    * ВСЕ toggles = false by default (ship hygiene, memory
      [[project_deltahack_ship_defaults_off]])

  - Status logic (последний фикс):
    * KNOCKED статус гейтится через show_*_hp toggle
    * DEAD гейтится через show_corpses (skip'ает всю entity)


7. ANTI-DETECT STACK
────────────────────
Слой за слоем чтобы усложнить анализ + минимизировать сигнатурный след:

  a) VMProtect Ultra:
     - Оба payload (dh_loader.exe) и launcher (WinRuntimeHost.exe) обёрнуты
     - Ultra mode: virtualization + mutations
     - Markers: VMProtectBeginUltra("resolve_key"), ...End
     - Wrapper Con.exe post-build

  b) KFPL AES-256-GCM обёртка:
     - Payload лежит зашифрованным до самого запуска
     - Header: "DHKF" magic + version + nonce(12) + ct_len(8) + ciphertext + tag(16)
     - Ключ per-release rotation (bake.py генерит fresh random)
     - Расшифровка in-memory только когда spawn'ится, temp .exe deleted-on-open

  c) Direct syscalls (SysWhispers2-style):
     - dh_syscalls.c walks ntdll.exports, sort by RVA, syscall# = index
     - g_ssn_NtQSI populated at DhInitSyscalls()
     - ASM stub: mov r10, rcx; mov eax, [g_ssn_NtQSI]; syscall; ret
     - Bypass user-mode ntdll hooks EDR/AV

  d) AMSI + ETW blind:
     - Custom patch bytes (не publicly-known signatures):
       AMSI: XOR EAX,EAX + ADD EAX,0x80070057 + RET
       ETW:  XOR RAX,RAX + RET on EtwEventWrite family + NtTraceEvent
     - AV scanners hunt B8 57 00 07 80 C3 → мы имеем 31 C0 05 57 00 07 80 C3

  e) Anti-debug:
     - PEB.BeingDebugged check
     - NtQueryInfoProcess(ProcessDebugPort=7)
     - NtQueryInfoProcess(ProcessDebugFlags=0x1F)
     - Silent ExitProcess on detection (no debug message)

  f) Anti-VM:
     - CPUID leaf 1 bit 31 (hypervisor present bit)
     - Log-only for beta (Hyper-V VM detection = false positive too high)

  g) PDB strip:
     - Build flags: /DEBUG:NONE /PDBALTPATH:$_PDB$
     - String "C:\DeltaHack\loader\build\dh_loader.pdb" не появляется в exe

  h) Per-build unique SHA256:
     - Post-build powershell appends 4-16 KB random bytes past PE end
     - SizeOfImage игнорирует, Windows loader OK
     - Ban wave по SHA burns только один build

  i) Log gating:
     - /DDH_RELEASE kills DH_INFO / DH_TRACE at compile time
     - Only DH_WARN / DH_ERROR / DH_FATAL survive → минимум log noise
     - Log path anonymized: %LOCALAPPDATA%\Microsoft\Windows\DiagnosticCache\core.log

  j) Shmem / event naming:
     - Fixed GUIDs вместо "DeltaHackEsp" / "DeltaHackStop":
       Shmem: Global\{7A9F3B21-4E2D-4B12-A5F7-8D6E4C9F1B3A}
       Stop:  Global\{7A9F3B22-4E2D-4B12-A5F7-8D6E4C9F1B3A}
       Ready: Global\{DHREADY-4EC7A38D-91B2-4C6A-9F32-DE8B7C51F2A0}
     - Не выдают продукт по имени объекта в WinObj

  k) Binary rename:
     - dh_loader.exe → embedded в bundle.kfpl (расшифрован в random-name %TEMP%)
     - Launcher stub называется WinRuntimeHost.exe (generic Windows-alike)

  l) WDA_EXCLUDEFROMCAPTURE:
     - Overlay-окно невидимо для OBS/Discord/ShadowPlay screen capture
     - НЕ спасает от NvFBC / AMD DisplayCapture (driver-level) —
       memory [[project_ace_screencap_methods_2026_07_22]] — ACE использует их
     - Intel iGPU safe


8. RUNTIME CAGE + SELF-DELETE
─────────────────────────────
При запуске WinRuntimeHost.exe от KoenFlow launcher:

  1. Оригинальный экземпляр (из KoenFlow cache):
     - Проверяет env DH_CAGE. Если нет → cage-move.
     - Создаёт %LOCALAPPDATA%\Microsoft\Windows\SystemCache\{random-GUID}\
     - Копирует туда WinRuntimeHost.exe + bundle.kfpl + db\*
     - Спавнит cage-copy с DH_CAGE=1, DH_INSTALL_DIR=<cage>,
                        DH_LAUNCHER_CACHE=<KoenFlow product dir>
     - Exit 0

  2. Cage-copy (DH_CAGE=1):
     - Спавнит daemon-esp + overlay-imgui children (детач, no window)
     - Спавнит janitor.bat в %TEMP% (random 4-byte name, hidden attr)
     - Exit 0

  3. Janitor batch:
     - timeout 10s (grace для спавна children)
     - Loop: tasklist "WinRuntimeHost.exe" → есть? → sleep 3s → loop
     - Когда все WinRuntimeHost.exe умерли → sleep 5s (grace на handle release)
     - rmdir /s /q <cage>
     - rmdir /s /q <launcher_cache>   (KoenFlow product dir)
     - del %~f0

Итог после закрытия игры:
  - Cage folder — wiped
  - Launcher cache folder — wiped
  - Janitor.bat — self-delete
  - На диске остаётся только KoenFlow's launcher.log с "product exited code 0"


9. ERROR CODES (KoenFlow launcher DHModal)
──────────────────────────────────────────
Reference: docs/DHMODAL_ERROR_CODES.md in the launcher repo
           (github.com/Nightvex-Labs/launcher).

User-actionable (#1..#9): the launcher shows the reason so the user can fix it.
  #1  Already running (close the running instance)
  #2  Windows Defender realtime is on (please disable)
  #3  Windows version unsupported (needs Win11 21H2..25H2)
  #4  Third-party antivirus detected (please disable)
  #5  License inactive or expired
  #6  Not enough free disk space
  #7  HVCI is enabled (reserved; DeltaHack works with HVCI on)
  #8  Administrator rights required
  #9  Delta Force is already running (close the game first)

Our-side (#10..#17): the launcher shows "please contact support" but the
number lets support pinpoint the pipeline stage.
  #10 update-server unreachable        #14 payload PE corrupt (AV gutted)
  #11 download failed                  #15 LaunchAsync generic failure
  #12 install failed                   #16 ready-event timeout (30s)
  #13 update-block exception           #17 reserved (bridge exception)

Ready-event contract:
  Global\{DHREADY-4EC7A38D-91B2-4C6A-9F32-DE8B7C51F2A0}   (manual reset event)
  Payload signals it once daemon-esp is armed. Launcher waits up to 30s.


10. KOENFLOW LAUNCHER INTEGRATION
────────────────────────────────
KoenFlow — .NET 8.0 WPF + WebView2 лаунчер (репо Nightvex-Labs/launcher).

Наш продукт зарегистрирован как productId = "deltaforce".

Launch flow (после нашего пересборки лаунчера):
  1. User нажимает "Launch" на карточке Delta Force
  2. Home.html → JS bridge → C# ShellBridge.LaunchProductAsync
  3. Pre-check: EventWaitHandle.TryOpenExisting("Global\{DHREADY-...}"):
     - Exists? → return error #1 "Already running"
  4. License check + product install verify
  5. Spawn WinRuntimeHost.exe с launch-context arg
  6. Async wait: EventWaitHandle открывается + WaitOne(30 sec)
     - Signaled → post product.dhstate phase=dh-running → модалка "Запущено"
     - Timeout → post phase=dh-error errorCode=99 → модалка "Ошибка №99"

Модалка (home.html):
  Состояния:
    - loading   — "Загрузка…" (со спиннером)
    - starting  — "Запуск…"
    - running   — "Запущено. Закройте лаунчер и запустите игру." (✓ иконка)
    - error     — "Ошибка №N: <текст>" (✗ иконка)

  Error codes (расширяемая):
    #1  = Уже запущено
    #2  = Bundle error (kfpl decrypt/load)
    #3  = Отключите Windows Defender
    #4  = Отключите HVCI
    #9  = Лицензия не активна
    #99 = Неизвестная ошибка (timeout / unknown)

Ready event сигнал от daemon-esp в main.c:
  Global\{DHREADY-4EC7A38D-91B2-4C6A-9F32-DE8B7C51F2A0}  (manual reset event)
  Создаётся после успеха: driver_up + RpmFindSystemCR3 + DaemonEspEnsureShmem
  SetEvent → лаунчер видит → флип модалки на "Запущено"


10. BUILD PIPELINE
──────────────────
Loader (C, MSVC):
  cd C:\DeltaHack\loader
  build.bat
  → build\dh_loader.exe

Post-build:
  - VMProtect_Con.exe wraps SDK markers
  - Random padding appended (per-build unique SHA)
  → dh_loader.vmp.exe → renamed to dh_loader.exe

Launcher (C, MSVC):
  cd C:\DeltaHack\launcher
  build.bat
  → build\App.exe
  VMProtect wrap → App.vmp.exe → WinRuntimeHost.exe

KFPL pack:
  python scripts\pack_kfpl.py loader\build\dh_loader.exe \
                              launcher\embed\dh_loader.kfpl \
                              [--key-hex XX...]
  → dh_loader.kfpl (renamed to bundle.kfpl at zip stage)

Bake (rotates KFPL key per release):
  python launcher\bake.py
  → pack_kfpl.py + bakes new hex key into launcher\src\dh_launcher.c

Zip:
  WinRuntimeHost.exe + bundle.kfpl + db\inpoutx64.bin
  → release\WinRuntimeHost.zip


11. FLAGS / CONFIG
──────────────────
Compile-time:
  /DDH_RELEASE          — silences DH_INFO/DH_TRACE
  /DDH_LAUNCHER_VERBOSE — bring back MessageBox popups (dev only)

Environment:
  DH_INSTALL_DIR        — provider .bin search override
  DH_CAGE=1             — cage-copy marker (set internally)
  DH_LAUNCHER_CACHE     — passed to janitor for launcher-cache wipe
  DH_KFPL_KEY_B64       — override baked KFPL key (base64)
  DH_KFPL_KEY_HEX       — override baked KFPL key (hex)

Named objects:
  Global\{7A9F3B21-...} — ESP shmem
  Global\{7A9F3B22-...} — stop event (Delta exit → SetEvent → overlay exits)
  Global\{DHREADY-...}  — ready event (daemon armed → SetEvent → лаунчер видит)


12. KNOWN LIMITATIONS / TODO
────────────────────────────
Test-release blockers ([[project_deltahack_release_todo_2026_09_23]]):
  - Weapon slot resolve не финализирован (алго cracked, integration pending)
  - Ammo counter reader
  - Loot filtering ancestor-chain

Anti-detect gaps:
  - kdu shellcode остаётся в ntoskrnl.exe pool до перезагрузки
    (нет DhProviderUnmap функции — задокументировано, риск reboot-recovery low)
  - Nothing blocks driver-level screencap (NvFBC / AMD AMF)
    — использовать Intel iGPU или менять WDA

Position decrypt:
  - Некоторые relevance-group entities возвращают zero positions (UcDecrypt
    header sanity fail) — orthogonal issue, investigate live


13. FORENSIC TRAIL (что остаётся)
─────────────────────────────────
После нормального exit:
  - KoenFlow launcher.log: "[launch:deltaforce] loader exited cleanly"
    (no product-name / no files)
  - launch-contexts/*.json — auto-cleanup ≤15 min (DPAPI-wrapped)
  - Возможно: kdu shellcode в ntoskrnl pool (invisible from userland)
  - Windows Prefetch: WINRUNTIMEHOST-<HASH>.pf, INPOUTX64.SYS-<HASH>.pf
  - EventLog System: 7045 (SCM service install/remove)

При abnormal exit (crash / kill):
  - Cage folder может остаться (janitor не запустится)
  - launcher.log с exit code != 0
  - Watson dumps в %LOCALAPPDATA%\CrashDumps\ (если WER on)


================================================================================
  End of DELTAHACK_README.txt
================================================================================
