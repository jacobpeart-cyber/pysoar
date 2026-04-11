@echo off
REM Build a single-file PySOAR agent binary for Windows.
REM
REM PyInstaller is not a cross-compiler: run this from a Windows host
REM to produce pysoar-agent-windows-<arch>.exe.
REM
REM Output: dist\pysoar-agent-windows-<arch>.exe  (self-contained, zero deps)

setlocal enabledelayedexpansion

cd /d "%~dp0"

echo [build] Installing build deps...
python -m pip install --quiet -r requirements-build.txt || goto :fail

for /f %%I in ('python -c "import platform;print(platform.machine().lower())"') do set ARCH=%%I
set OUT_NAME=pysoar-agent-windows-%ARCH%

echo [build] Bundling pysoar_agent.py into dist\%OUT_NAME%.exe ...
python -m PyInstaller ^
    --onefile ^
    --noconfirm ^
    --clean ^
    --name pysoar-agent ^
    --distpath .\dist ^
    --workpath .\build-tmp ^
    --specpath .\build-tmp ^
    pysoar_agent.py || goto :fail

move /Y .\dist\pysoar-agent.exe .\dist\%OUT_NAME%.exe >nul

for /f %%I in ('python -c "import hashlib,sys;print(hashlib.sha256(open(r'dist\%OUT_NAME%.exe','rb').read()).hexdigest())"') do set HASH=%%I

echo.
echo [build] OK
echo   binary: dist\%OUT_NAME%.exe
echo   sha256: %HASH%
echo.
echo [build] Test with:  dist\%OUT_NAME%.exe --help
exit /b 0

:fail
echo [build] FAILED
exit /b 1
