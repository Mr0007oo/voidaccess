@echo off
cd /d "%~dp0"

if not exist ".env" (
    echo [!] No .env file found. Run setup first:
    echo     setup.bat  ^(Windows^)
    echo     bash setup.sh  ^(Git Bash / WSL^)
    pause
    exit /b 1
)

echo.
echo Starting VoidAccess...
echo.

%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
    "$env:DOCKER_BUILDKIT=1; docker compose -f '%~dp0infra/docker-compose.yml' --project-directory '%~dp0' --env-file '%~dp0.env' up --build -d; exit $LASTEXITCODE"

if errorlevel 1 (
    echo.
    echo [!] Docker Compose failed to start. Check the output above.
    pause
    exit /b 1
)

echo.
echo Waiting for services to be ready...

%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
    "$status = ''; for ($i = 0; $i -lt 60; $i++) { try { $r = Invoke-RestMethod 'http://localhost:8000/healthz/ready' -TimeoutSec 5 -EA Stop; if ($r.status -eq 'ready') { $status = 'ready'; break } } catch {} Write-Host -NoNewline '.'; Start-Sleep 5 }; Write-Host ''; if ($status -eq 'ready') { Write-Host ''; Write-Host ' +==========================================+'; Write-Host ' |       VoidAccess is ready!              |'; Write-Host ' +==========================================+'; Write-Host ' |  Web UI:   http://localhost:3001        |'; Write-Host ' |  API:      http://localhost:8000        |'; Write-Host ' |  API docs: http://localhost:8000/docs   |'; Write-Host ' +==========================================+'; Write-Host ' |  Stop:  stop.bat                       |'; Write-Host ' +==========================================+' } else { Write-Host '[!] Services taking longer than expected.'; Write-Host '    Check: docker compose -f infra/docker-compose.yml logs -f' }"
