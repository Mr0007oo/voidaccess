@echo off
:: Restart in a fresh cmd session so ANSI escape codes render correctly
if not defined VA_COLORS_ENABLED (
    set VA_COLORS_ENABLED=1
    reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1 /f >nul 2>&1
    cmd /c "%~f0" %*
    exit /b
)

setlocal enabledelayedexpansion
chcp 65001 >nul
cd /d "%~dp0"

:: ── Color setup ──────────────────────────────────────────────────────────────
set "ESC="
for /f %%a in ('echo prompt $E^| cmd') do set "ESC=%%a"
set "GREEN=%ESC%[0;32m"
set "RED=%ESC%[0;31m"
set "YELLOW=%ESC%[1;33m"
set "CYAN=%ESC%[0;36m"
set "BOLD=%ESC%[1m"
set "DIM=%ESC%[2m"
set "NC=%ESC%[0m"

:: ── Banner ────────────────────────────────────────────────────────────────────
echo.
echo %CYAN%  +===================================+%NC%
echo %CYAN%  ^|  VoidAccess  ·  Starting up       ^|%NC%
echo %CYAN%  +===================================+%NC%
echo.

:: ── Docker permission check ───────────────────────────────────────────────────
docker info >nul 2>&1
if errorlevel 1 (
    echo %YELLOW%  [^!^!]%NC%  Docker not running or not found.
    echo   %DIM%-^>%NC%  Start Docker Desktop and try again.
    echo   %DIM%-^>%NC%  Download: https://docs.docker.com/get-docker/
    pause
    exit /b 1
)

:: ── .env check ───────────────────────────────────────────────────────────────
if not exist ".env" (
    echo %YELLOW%  [^!^!]%NC%  No .env file found. Run setup first:
    echo   %DIM%-^>%NC%  setup.bat
    pause
    exit /b 1
)

:: ── Build ^& start ────────────────────────────────────────────────────────────
echo %DIM%   -^>%NC%  Building containers...
set DOCKER_BUILDKIT=1
docker compose -f infra\docker-compose.yml --project-directory "%~dp0" --env-file "%~dp0.env" up --build -d > "%TEMP%\va_start.log" 2>&1
if errorlevel 1 (
    echo %RED%  [^!^!]%NC%  Build failed — check %TEMP%\va_start.log
    pause
    exit /b 1
)
echo %GREEN%  [OK]%NC%  Containers started

:: ── Service health ────────────────────────────────────────────────────────────
echo.
echo %DIM%   -^>%NC%  Waiting for services...

for %%S in (postgres tor fastapi nextjs) do (
    set "READY=0"
    for /l %%i in (1,1,30) do (
        if "!READY!"=="0" (
            docker inspect --format "{{.State.Health.Status}}" voidaccess-%%S >nul 2>&1
            if not errorlevel 1 (
                echo %GREEN%  [OK]%NC%  %%S
                set "READY=1"
            ) else (
                timeout /t 2 /nobreak >nul
            )
        )
    )
    if "!READY!"=="0" (
        echo %YELLOW%  [^!^!]%NC%  %%S (timeout)
    )
)

:: ── Wait for API ready ────────────────────────────────────────────────────────
echo.
set STATUS=
set /a COUNT=0
:WAIT
if !COUNT! geq 60 goto SHOW_RESULT
for /f "delims=" %%i in ('curl -s --max-time 5 http://localhost:8000/healthz/ready 2^>nul') do set RESPONSE=%%i
echo !RESPONSE! | findstr /c:"ready" >nul 2>&1
if not errorlevel 1 set STATUS=ready
if "!STATUS!"=="ready" goto SHOW_RESULT
set /a COUNT+=1
timeout /t 5 /nobreak >nul
goto WAIT

:: ── Ready banner ──────────────────────────────────────────────────────────────
:SHOW_RESULT
if "!STATUS!"=="ready" (
    echo.
    echo %GREEN%  +===================================+%NC%
    echo %GREEN%  ^|                                   ^|%NC%
    echo %GREEN%  ^|   [OK]  VoidAccess is ready       ^|%NC%
    echo %GREEN%  ^|                                   ^|%NC%
    echo %GREEN%  ^|   UI  -^>  http://localhost:3001   ^|%NC%
    echo %GREEN%  ^|   API -^>  http://localhost:8000   ^|%NC%
    echo %GREEN%  ^|                                   ^|%NC%
    echo %GREEN%  +===================================+%NC%
    echo.
) else (
    echo %YELLOW%  [^!^!]%NC%  Services are taking longer than expected.
    echo   %DIM%-^>%NC%  docker compose -f infra\docker-compose.yml --project-directory . ps
    echo   %DIM%-^>%NC%  docker compose -f infra\docker-compose.yml --project-directory . logs -f
)

exit /b 0
