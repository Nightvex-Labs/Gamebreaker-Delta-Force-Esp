# DeltaHack — Инструкция по упаковке релиза

Полный pipeline от исходников до финального `WinRuntimeHost.zip` который
загружается в KoenFlow admin panel. Один запуск от нуля до готового ZIP.

---

## 0. Требования (один раз)

- **Windows 11 x64** (build 22000+ или 26100+)
- **Visual Studio 2022 Community** с MSVC 14.44 + Win11 SDK 26100
  (стандартный `Desktop development with C++` workload)
- **Python 3.10+** с `cryptography` пакетом:
  `pip install cryptography`
- **VMProtect Ultimate 3.9.4** — `C:\DeltaHack\tools\vmprotect\notVmp\VMProtect_Con.exe`
  (лицензированная копия; input/output через CLI без GUI)
- **Unicorn Engine 2.1.4 static libs** — уже лежат в `C:\DeltaHack\deps\unicorn\static\`
- **Git Bash** для shell-скриптов (bake, pack) или PowerShell 7+

Проверка среды одной командой:
```powershell
where cl.exe                              # MSVC compiler
where python                              # Python
Test-Path C:\DeltaHack\tools\vmprotect\notVmp\VMProtect_Con.exe
Test-Path C:\DeltaHack\deps\unicorn\static\lib\unicorn.lib
```

---

## 1. Layout репозитория

```
C:\DeltaHack\
├── loader\               ← payload (dh_loader.exe)
│   ├── src\              исходники
│   ├── inc\              headers
│   ├── deps\             imgui, vmprotect SDK, stb
│   ├── build.bat         one-shot loader build
│   └── build\            output (dh_loader.exe)
├── launcher\             ← KFPL wrapper stub
│   ├── src\              dh_launcher.c + dh_crash_upload.c
│   ├── embed\            output KFPL blob (dh_loader.kfpl)
│   ├── build.bat         one-shot launcher build
│   ├── bake.py           pack + zero-key inject
│   └── build\            output (App.exe, App.vmp.exe)
├── scripts\
│   ├── pack_kfpl.py      AES-256-GCM wrapper
│   └── make_release_zip.py  full end-to-end pipeline
└── release\
    └── WinRuntimeHost.zip   ← финальный релиз
```

---

## 2. Быстрая полная сборка (один шаг)

```bash
cd C:\DeltaHack
python scripts\make_release_zip.py
```

Всё делает сам: build loader → bake ZERO KFPL key → build launcher →
VMProtect wrap → DHBE trailer → zip. В конце выводит:

```
========================================================================
  SHIP: C:\DeltaHack\release\WinRuntimeHost.zip
    size:   41,971,291 B
    sha256: 15877330412a331b4ce831ce6e789507faa5b4cb7d977d2cc222ee729846653a
========================================================================
```

Плюс в консоли — **KFPL KEY** для админ-панели:
```
========================================================================
  KFPL KEY (paste into site's upload form, KFPL KEY field):

    hex:    190ab3b7b5c285e6c037b6722c1da77c0dc752109db2c5d3aa8886f3324037ae
    b64:    GQqzt7XChebAN7ZyLB2nfA3HUhCdssXTqoiG8zJAN64=

  Backend must inject env DH_KFPL_KEY_B64/_HEX (or write it into
  the DPAPI-wrapped launch-context JSON) at Play time.
========================================================================
```

---

## 3. Ручная сборка (пошагово, для debug)

### 3.1 Build loader

```bash
cd C:\DeltaHack\loader
build.bat
```

Output: `build\dh_loader.exe` ~28 MB. Loader **не** содержит VMProtect
markers — это payload, wrap делает launcher stub.

### 3.2 Bake KFPL

```bash
cd C:\DeltaHack\launcher
python bake.py
```

Что делает:
1. Runs `scripts\pack_kfpl.py` — генерит fresh AES-256 key, encrypts
   `loader\build\dh_loader.exe` → `launcher\embed\dh_loader.kfpl`
   (магия `DHKF`, AES-256-GCM с AAD=`DHKF`)
2. Проверяет base64 ключа на отсутствие `+` и `/` (админка их обрезает) —
   до 30 попыток пока не получит чистый b64
3. Записывает `KFPL_KEY[32] = { 0x00, 0x00, ... }` (all-zero) в
   `launcher\src\dh_launcher.c` — release режим, ключ **не в бинарнике**
4. Печатает hex + b64 ключа для админ-панели

Для локальной dev-сборки (bake **реального** ключа в exe — небезопасно
для prod):
```bash
python bake.py --bake
```

### 3.3 Build launcher stub

```bash
cd C:\DeltaHack\launcher
build.bat
```

Output: `build\App.exe` ~170 KB. Содержит VMProtect markers для:
- `resolve_key`
- `extract_key_from_launch_context`
- `aes_gcm_decrypt`
- `antitheft_guard`

### 3.4 VMProtect wrap

```bash
"C:\DeltaHack\tools\vmprotect\notVmp\VMProtect_Con.exe" ^
    "C:\DeltaHack\launcher\build\App.exe" ^
    "C:\DeltaHack\launcher\build\App.vmp.exe"
```

Output: `build\App.vmp.exe` ~13-15 MB (4 функции virtualized в VM
bytecode). Смотри `Ultra` markers в консоли VMProtect:
```
[U] 1400012E5 VMProtectMarker "extract_key_from_launch_context"
[U] 1400019D3 VMProtectMarker "resolve_key"
[U] 140001C5B VMProtectMarker "antitheft_guard"
[U] 14000211A VMProtectMarker "aes_gcm_decrypt"
```

### 3.5 DHBE self-trailer + zip

```python
import struct, zipfile
stub   = open(r'C:\DeltaHack\launcher\build\App.vmp.exe', 'rb').read()
bundle = open(r'C:\DeltaHack\launcher\embed\dh_loader.kfpl', 'rb').read()

# Single-file exe: append bundle past PE end + 12-byte trailer
trailer = struct.pack('<Q', len(bundle)) + b'DHBE'
with open(r'C:\DeltaHack\release\WinRuntimeHost.exe', 'wb') as f:
    f.write(stub); f.write(bundle); f.write(trailer)

# Zip 3 files (WinRuntimeHost.exe embeds bundle, sidecar dll+driver stay)
with zipfile.ZipFile(r'C:\DeltaHack\release\WinRuntimeHost.zip', 'w',
                     zipfile.ZIP_DEFLATED) as z:
    z.write(r'C:\DeltaHack\release\WinRuntimeHost.exe', 'WinRuntimeHost.exe')
    z.write(r'C:\DeltaHack\loader\deps\vmprotect\lib\VMProtectSDK64.dll',
            'VMProtectSDK64.dll')
    z.write(r'C:\DeltaHack\loader\src\db\inpoutx64.bin', 'db/inpoutx64.bin')
```

---

## 4. Загрузка в KoenFlow admin panel

1. Открой https://koenflow.com admin panel → Products → **Delta Force ESP**
2. Upload → **Package** field → выбрать `C:\DeltaHack\release\WinRuntimeHost.zip`
3. **Launch executable** field → `WinRuntimeHost.exe`
4. **KFPL KEY** field → вставить `b64` строку из вывода `bake.py`
   (например `GQqzt7XChebAN7ZyLB2nfA3HUhCdssXTqoiG8zJAN64=`)
5. Save → новый релиз доступен клиентам

---

## 5. Проверка что упаковка правильная

Перед загрузкой в KoenFlow — smoke-test локально:

### 5.1 Trailer sanity

```powershell
$exe = 'C:\DeltaHack\release\WinRuntimeHost.exe'
$sz  = (Get-Item $exe).Length
$fs  = [System.IO.File]::OpenRead($exe)
$fs.Seek($sz - 4, 'Begin') | Out-Null
$magic = New-Object byte[] 4; $fs.Read($magic, 0, 4) | Out-Null
$fs.Close()
[System.Text.Encoding]::ASCII.GetString($magic)   # должно вывести "DHBE"
```

### 5.2 VMProtect linkage

```powershell
& 'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe' /IMPORTS `
    C:\DeltaHack\release\WinRuntimeHost.exe | Select-String "VMProtectSDK64"
```
Должно показать `VMProtectSDK64.dll` в imports.

### 5.3 KFPL blob сanity

```powershell
$b = [System.IO.File]::ReadAllBytes('C:\DeltaHack\launcher\embed\dh_loader.kfpl')
[System.Text.Encoding]::ASCII.GetString($b[0..3])   # должно вывести "DHKF"
```

### 5.4 Zip integrity

```powershell
Get-ChildItem C:\DeltaHack\release\WinRuntimeHost.zip
Expand-Archive C:\DeltaHack\release\WinRuntimeHost.zip -DestinationPath $env:TEMP\dhtest -Force
Get-ChildItem $env:TEMP\dhtest -Recurse | Format-Table Name, Length
Remove-Item $env:TEMP\dhtest -Recurse -Force
```
Ожидается 3 файла: `WinRuntimeHost.exe`, `VMProtectSDK64.dll`, `db\inpoutx64.bin`.

---

## 6. Troubleshooting

| Симптом | Причина | Fix |
|---|---|---|
| `build.bat` падает с "vcvars64.bat not found" | MSVC не установлен или не в стандартном путе | Установить VS 2022 или поправить путь в `build.bat` |
| `bake.py` — `cryptography not installed` | Отсутствует Python пакет | `pip install cryptography` |
| `VMProtect_Con.exe not found` | Путь не совпадает | Правь `scripts\vmprotect_wrap.py` `VMP_CANDIDATES` |
| `+` или `/` в b64 → админка обрезает | Base64 unsafe символы | `bake.py` уже loop'ает до clean b64 (до 30 попыток) |
| KoenFlow Error #14 (payload_corrupt) | AV удалил `WinRuntimeHost.exe` при extract | Whitelist `%LOCALAPPDATA%\KoenFlowLauncher\products\deltaforce\current\` в Defender |
| KoenFlow Error #12 (install failed) | Locked file от предыдущего запуска | Close NightvexLauncher полностью, подождать 30 сек, retry |
| Clients: `dh_launcher.log — decrypt fail NTSTATUS=0xC000A002` | Wrong KFPL key в админке | Верни правильный `b64` в KoenFlow admin |

---

## 7. Клиентские логи для support

Если у клиента что-то не работает — попроси прислать:

```
%TEMP%\dh_launcher.log                                        (KFPL stub trace)
C:\Users\Public\dh_reader.log                                 (per-tick reader diag)
C:\Users\Public\dh_procs.log                                  (30s tasklist snapshots)
%LOCALAPPDATA%\Microsoft\Windows\DiagnosticCache\core.log     (payload WARN/ERROR)
%LOCALAPPDATA%\KoenFlowLauncher\logs\launcher.log             (KoenFlow itself)
```

Плюс автоматически всё это уходит на `https://koenflow.com/api/telemetry/crash`
после каждого exit'а payload'а. Server dir key = SHA256(MachineGuid|ComputerName).
Смотри `/var/log/abi-crash/<hash>/` на koenflow VPS.

---

## 8. Что попадает на телеметрию сервера

После каждого запуска (payload exit → launcher POST):

**Metadata JSON** (`ts_vdh-1.0.0_b26220_ec0x00000001.json`):
- `license_hash`, `version`, `os_build`, `exit_code`, `parent_pid`, `child_pid`

**Attachments** (multipart fields `ah_launcher` / `ah_reader` / `ah_procs` /
`ah_crashmeta` / `ah_dump`):
- `_launcher.log.gz` — KFPL stub trace
- `_reader.log.gz` — per-tick stats (uc_ready, count, alive, myX/Y/Z, hz)
- `_procs.log.gz` — 30s process snapshots
- `_crashmeta.txt` — SEH context (RIP/RSP/GPR + backtrace) при краше
- `_dump.dmp` — MiniDumpNormal + ThreadInfo при краше

---

## 9. Checklist перед публикацией нового релиза

- [ ] `python scripts\make_release_zip.py` выполнился без ошибок
- [ ] `release\WinRuntimeHost.zip` создался (~40-42 MB)
- [ ] SHA256 в консоли записан для changelog
- [ ] KFPL b64 ключ скопирован (внимание: **новый на каждый релиз**)
- [ ] Smoke-tested локально: extract zip → запуск WinRuntimeHost.exe без
      контекста → silent exit (anti-piracy сработал), с KOENFLOW env вар
      → decrypt OK → child spawned
- [ ] Old dev-only `--bake` builds **не публикуются** (ключ утечёт из
      `.rdata` секции)
- [ ] Commit в GitHub (`Nightvex-Labs/deltahack`) с описанием изменений
- [ ] Upload в KoenFlow admin panel + вставка нового `b64` ключа
- [ ] Уведомить тестеров в Discord/Telegram
