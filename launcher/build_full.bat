@echo off
REM One-shot orchestrator: pack dh_loader.kfpl with a FRESH random key,
REM inject key bytes into src/dh_launcher.c, then build the launcher exe.

setlocal

if not exist ..\loader\build\dh_loader.exe (
  echo [orch] ..\loader\build\dh_loader.exe missing - build loader first
  exit /b 1
)

pushd "%~dp0"
if not exist embed mkdir embed
if not exist build mkdir build

echo [orch] pack + bake + build (fresh AES-256 key each run)
python bake.py
if errorlevel 1 (echo [orch] pack/bake failed & popd & exit /b 2)

call "%~dp0build.bat"
if errorlevel 1 (echo [orch] launcher build failed & popd & exit /b 3)

echo.
echo [orch] SHIP: launcher\build\dh_launcher.exe
popd
