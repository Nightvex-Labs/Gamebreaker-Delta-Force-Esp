@echo off
REM DeltaHack launcher build — outputs build\App.exe (no embedded resource,
REM reads bundle.kfpl from same directory as itself at runtime).

setlocal
set VCVARS="C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist %VCVARS% (
  echo [build] vcvars64.bat not found at %VCVARS%
  exit /b 2
)
call %VCVARS% >nul
if errorlevel 1 (echo [build] vcvars64 failed & exit /b 3)

pushd "%~dp0"
if not exist build mkdir build

echo [build] compiling launcher -^> build\App.exe
set CFLAGS=/nologo /W3 /O2 /GS- /MT /D_UNICODE /DUNICODE /D_WIN32_WINNT=0x0A00 /DDH_VMPROTECT /Iinc
REM VMProtect SDK linked so VMProtectBeginUltra/End markers survive linking.
REM Post-build VMProtect_Con.exe wrap virtualizes marker regions.
REM /SUBSYSTEM:WINDOWS — kills the brief CONSOLE window flash that would
REM otherwise appear when the KoenFlow launcher spawns us with
REM CreateNoWindow=false (BackendProductLaunchService default). wmain still
REM works under WINDOWS subsystem with the wmainCRTStartup entry — the CRT
REM startup routine parses argv the same way, just doesn't allocate a console.
REM VMProtect linkage — see loader/build.bat comment. Post-build wrap needed.
set LFLAGS=/link /SUBSYSTEM:WINDOWS /ENTRY:wmainCRTStartup /OPT:REF /OPT:ICF /LIBPATH:..\loader\deps\vmprotect\lib Bcrypt.lib Kernel32.lib User32.lib Shlwapi.lib VMProtectSDK64.lib
cl %CFLAGS% src\dh_launcher.c /Fe:build\App.exe /Fo:build\ %LFLAGS%
if errorlevel 1 (echo [build] FAILED & popd & exit /b 4)

echo [build] OK -^> build\App.exe
dir /b build\App.exe
popd
