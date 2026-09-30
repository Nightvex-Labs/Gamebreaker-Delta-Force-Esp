@echo off
REM DeltaHack loader — one-shot build wrapper.
REM  - loads vcvars64 (MSVC 14.44 + Win11 SDK 26100 auto-picks)
REM  - compiles src\*.c into build\dh_loader.exe
REM  - unicode entry (wmain), static CRT, no incremental link

setlocal
REM Auto-pick MSVC 2022 edition (Community/Professional/Enterprise/BuildTools).
set VCVARS=
for %%E in (Community Professional Enterprise BuildTools) do (
  if not defined VCVARS (
    if exist "C:\Program Files\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat" set VCVARS="C:\Program Files\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat"
    if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat" set VCVARS="C:\Program Files (x86)\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat"
  )
)
if not defined VCVARS (
  echo [build] vcvars64.bat not found under any 2022 edition
  exit /b 2
)

call %VCVARS% >nul
if errorlevel 1 (
  echo [build] vcvars64 failed
  exit /b 3
)

pushd "%~dp0"
if not exist build mkdir build

REM dh_overlay*.cpp + dh_ui\*.cpp compile separately under DHUI_FLAGS because
REM they use ImGui's headers heavily (/W4 /WX would trip on imgui warnings)
REM and pull in utf-8 Cyrillic string literals from the Spectra menu port.
REM dh_system_spawn.c is the upstream SYSTEM-elevation fix — kept in main SRC.
set SRC=src\main.c src\log.c src\dh_mz_wipe.c src\dh_diag.c src\dh_item_catalog.c src\db\dh_dbunpack.c src\svc\dh_scm.c src\winio\dh_phys.c src\winio\dh_prov_registry.c src\winio\dh_prov_impl.c src\mem\dh_rpm.c src\decrypt\dh_ace_decrypt.c src\decrypt\dh_vtbl_decrypt.c src\decrypt\dh_c280_decrypt.c src\decrypt\dh_unicorn_decrypt.c src\decrypt\dh_state_cache.c src\decrypt\dh_spray.c src\decrypt\dh_derive_key.c src\overlay\dh_daemon_esp.c src\hollow\dh_hollow.c src\hardening\dh_amsi_etw.c src\hardening\dh_syscalls.c src\hardening\dh_auth.c src\hardening\dh_system_spawn.c
set OVERLAY_CPP=src\overlay\dh_overlay.cpp src\overlay\dh_overlay_imgui.cpp
set DHUI_CPP=src\dh_ui\menu_v3.cpp src\dh_ui\icons.cpp
set IMGUI=deps\imgui\imgui.cpp deps\imgui\imgui_draw.cpp deps\imgui\imgui_tables.cpp deps\imgui\imgui_widgets.cpp deps\imgui\backends\imgui_impl_win32.cpp deps\imgui\backends\imgui_impl_dx11.cpp deps\imgui\misc\freetype\imgui_freetype.cpp
set ASM=src\decrypt\vtbl_call_wrap.asm
set ASM2=src\decrypt\vtbl_spray_wrap.asm
set ASM3=src\hardening\dh_syscalls.asm
set OUT=build\dh_loader.exe

set UC_INC=..\deps\unicorn\static\include
set UC_LIB=..\deps\unicorn\static\lib

REM DH_RELEASE — kills DH_INFO / DH_TRACE at compile time; only DH_WARN /
REM DH_ERROR / DH_FATAL survive. Comment out to see gameplay logs for debug.
set CFLAGS=/nologo /W4 /WX /O2 /GS- /MD /D_UNICODE /DUNICODE /D_WIN32_WINNT=0x0A00 /DDH_RELEASE /Iinc /Ideps\imgui /I%UC_INC%
set IMFLAGS=/nologo /W0 /O2 /GS- /MD /EHsc /D_UNICODE /DUNICODE /D_WIN32_WINNT=0x0A00 /Ideps\imgui /Ideps\freetype\include
REM DHUI_FLAGS — Spectra menu port + overlay .cpp files. UTF-8 for Cyrillic
REM string literals, C++20 for menu_v3's designated initializers, ImGui/FreeType
REM include paths, warnings loose (/W1) — ImGui headers trip /W4 /WX.
set DHUI_FLAGS=/nologo /W1 /O2 /GS- /MD /EHsc /std:c++20 /utf-8 /D_UNICODE /DUNICODE /D_WIN32_WINNT=0x0A00 /DDH_RELEASE /Iinc /Ideps\imgui /Ideps\freetype\include
REM PDB strip: /PDBALTPATH:%%_PDB%% removes absolute path from PE debug entry,
REM /DEBUG:NONE prevents .pdb generation entirely for release-quality build.
REM Strings like "C:\DeltaHack\loader\build\dh_loader.pdb" disappear from exe.
REM KFPL restored 2026-09-27: loader is the payload (dh_loader.exe), launcher
REM stub (launcher/src/dh_launcher.c) is the KFPL wrapper that gets VMProtect'd
REM and ships as WinRuntimeHost.exe with the bundle embedded past its PE end.
REM Loader itself has NO VMProtect markers active and no VMProtectSDK64 link —
REM the decrypted payload runs standalone in %TEMP% without a DLL neighbor.
REM /SUBSYSTEM:WINDOWS — kills the CONSOLE window flash that KoenFlow-spawned
REM elevated launches would otherwise show. wmainCRTStartup entry still parses
REM argv identically. Overlay uses D3D11+DComp so no console needed for render.
set LFLAGS=/link /SUBSYSTEM:WINDOWS /ENTRY:wmainCRTStartup /OPT:REF /OPT:ICF /DEBUG:NONE /PDBALTPATH:%%_PDB%% /NODEFAULTLIB:MSVCRTD.lib /LIBPATH:%UC_LIB% /LIBPATH:deps\freetype\lib Advapi32.lib User32.lib Gdi32.lib winmm.lib unicorn.lib Shlwapi.lib Shell32.lib d3d11.lib dxgi.lib dxguid.lib dcomp.lib dwmapi.lib d2d1.lib dwrite.lib winhttp.lib crypt32.lib freetype.lib

echo [build] assembling %ASM% + %ASM2%
ml64 /nologo /c /Fo build\vtbl_call_wrap.obj %ASM%
if errorlevel 1 ( echo MASM failed & popd & exit /b 4 )
ml64 /nologo /c /Fo build\vtbl_spray_wrap.obj %ASM2%
if errorlevel 1 ( echo MASM2 failed & popd & exit /b 4 )
ml64 /nologo /c /Fo build\dh_syscalls_asm.obj %ASM3%
if errorlevel 1 ( echo MASM3 failed & popd & exit /b 4 )

echo [build] compiling ImGui (warnings suppressed)
cl %IMFLAGS% /c %IMGUI% /Fo:build\
if errorlevel 1 ( echo [build] ImGui FAILED & popd & exit /b 4 )

echo [build] compiling Spectra menu port + overlay .cpp (dh_ui + dh_overlay*)
cl %DHUI_FLAGS% /c %OVERLAY_CPP% %DHUI_CPP% /Fo:build\
if errorlevel 1 ( echo [build] DHUI FAILED & popd & exit /b 4 )

echo [build] compiling %SRC% -^> %OUT%
cl %CFLAGS% %SRC% build\vtbl_call_wrap.obj build\vtbl_spray_wrap.obj build\dh_syscalls_asm.obj build\imgui.obj build\imgui_draw.obj build\imgui_tables.obj build\imgui_widgets.obj build\imgui_impl_win32.obj build\imgui_impl_dx11.obj build\imgui_freetype.obj build\dh_overlay.obj build\dh_overlay_imgui.obj build\menu_v3.obj build\icons.obj /Fe:%OUT% /Fo:build\ %LFLAGS%
if errorlevel 1 (
  echo [build] FAILED
  popd
  exit /b 4
)

REM Per-user unique binary — append random padding (4-16KB) past PE end so
REM every build gets a distinct SHA256. Windows loader ignores bytes past
REM OptionalHeader.SizeOfImage. A ban wave on hash burns only the one build.
REM For production: server generates fresh padding per user download.
powershell -NoProfile -Command "$sz = Get-Random -Min 4096 -Max 16384; $b = New-Object byte[] $sz; (New-Object System.Random).NextBytes($b); [System.IO.File]::AppendAllBytes('build\dh_loader.exe', $b)" 2>nul

echo [build] OK -^> %OUT%
for %%A in (%OUT%) do echo   size: %%~zA bytes
for /f "delims=" %%H in ('certutil -hashfile %OUT% SHA256 ^| findstr /r "^[0-9a-f]"') do echo   sha256: %%H
dir /b build\dh_loader.exe
popd
