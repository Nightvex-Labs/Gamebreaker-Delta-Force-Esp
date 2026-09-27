@echo off
REM DeltaHack launcher — outputs build\App.exe. Reads bundle.kfpl from
REM DHBE self-trailer (after make_release_zip.py append) or sidecar.

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
set CFLAGS=/nologo /W3 /O2 /GS- /MT /D_UNICODE /DUNICODE /D_WIN32_WINNT=0x0A00
set LFLAGS=/link /SUBSYSTEM:WINDOWS /ENTRY:wmainCRTStartup /OPT:REF /OPT:ICF /LIBPATH:..\loader\deps\vmprotect\lib Bcrypt.lib Crypt32.lib Kernel32.lib User32.lib Shlwapi.lib Advapi32.lib VMProtectSDK64.lib
cl %CFLAGS% src\dh_launcher.c src\dh_crash_upload.c /Fe:build\App.exe /Fo:build\ %LFLAGS%
if errorlevel 1 (echo [build] FAILED & popd & exit /b 4)

echo [build] OK -^> build\App.exe
dir /b build\App.exe
popd
