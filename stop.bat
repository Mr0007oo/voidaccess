@echo off
cd /d "%~dp0"

echo.
echo Stopping VoidAccess...
echo.

%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
    "docker compose -f '%~dp0infra/docker-compose.yml' --project-directory '%~dp0' down; exit $LASTEXITCODE"

if errorlevel 1 (
    echo.
    echo [!] Failed to stop containers. Check the output above.
    pause
    exit /b 1
)

echo.
echo VoidAccess stopped.
echo.
