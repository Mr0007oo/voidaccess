@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo.
echo  VoidAccess Setup Wizard
echo  =======================
echo.

:: =============================================================================
:: STEP 1: Prerequisites
:: =============================================================================
echo [Step 1/7] Checking prerequisites...
echo.

where docker >nul 2>&1
if errorlevel 1 (
    echo [!] Docker not found.
    echo     Install Docker Desktop: https://docs.docker.com/desktop/install/windows-install/
    pause
    exit /b 1
)
echo [OK] Docker found.

docker compose version >nul 2>&1
if errorlevel 1 (
    echo [!] Docker Compose not found. Update Docker Desktop to a recent version.
    pause
    exit /b 1
)
echo [OK] Docker Compose found.

:: Check for Python (needed for secret generation)
set PYTHON=
python --version >nul 2>&1 && set PYTHON=python
if not defined PYTHON (
    python3 --version >nul 2>&1 && set PYTHON=python3
)
if not defined PYTHON (
    echo [!] Python not found. Install Python from https://python.org
    echo     Python is required to generate secure secrets.
    pause
    exit /b 1
)
echo [OK] Python found.
echo.

:: =============================================================================
:: STEP 2: .env setup
:: =============================================================================
echo [Step 2/7] Environment file...
echo.

if exist ".env" (
    set /p OVERWRITE="A .env file already exists. Overwrite? [y/N]: "
    if /i "!OVERWRITE!" neq "y" (
        echo Keeping existing .env.
        goto STEP3
    )
)

if exist ".env.example" (
    copy /y ".env.example" ".env" >nul
    echo [OK] Created .env from .env.example
) else (
    type nul > ".env"
    echo [OK] Created empty .env
)
echo.

:: =============================================================================
:: STEP 3: Generate secrets
:: =============================================================================
:STEP3
echo [Step 3/7] Generating secrets...
echo.

for /f "delims=" %%i in ('!PYTHON! -c "import secrets; print(secrets.token_hex(32))"') do set JWT_SECRET=%%i
for /f "delims=" %%i in ('!PYTHON! -c "import secrets; print(secrets.token_hex(16))"') do set POSTGRES_PASSWORD=%%i

call :env_set "JWT_SECRET" "!JWT_SECRET!"
call :env_set "POSTGRES_PASSWORD" "!POSTGRES_PASSWORD!"
echo [OK] Generated JWT_SECRET and POSTGRES_PASSWORD
echo.

:: =============================================================================
:: STEP 4: LLM provider
:: =============================================================================
echo [Step 4/7] LLM Provider
echo.
echo   [1] Groq        - FREE, fast (https://console.groq.com)
echo   [2] OpenRouter  - FREE tier available (https://openrouter.ai)
echo   [3] Anthropic   - Paid, best quality (https://console.anthropic.com)
echo   [4] OpenAI      - Paid (https://platform.openai.com)
echo   [5] Google      - FREE tier (https://aistudio.google.com)
echo   [6] Ollama      - FREE, local (https://ollama.ai)
echo   [7] Skip
echo.
set /p LLM_CHOICE="Choose [1-7]: "

if "!LLM_CHOICE!"=="1" (
    set /p LLM_KEY="Groq API key: "
    if defined LLM_KEY call :env_set "GROQ_API_KEY" "!LLM_KEY!"
)
if "!LLM_CHOICE!"=="2" (
    set /p LLM_KEY="OpenRouter API key: "
    if defined LLM_KEY call :env_set "OPENROUTER_API_KEY" "!LLM_KEY!"
)
if "!LLM_CHOICE!"=="3" (
    set /p LLM_KEY="Anthropic API key: "
    if defined LLM_KEY call :env_set "ANTHROPIC_API_KEY" "!LLM_KEY!"
)
if "!LLM_CHOICE!"=="4" (
    set /p LLM_KEY="OpenAI API key: "
    if defined LLM_KEY call :env_set "OPENAI_API_KEY" "!LLM_KEY!"
)
if "!LLM_CHOICE!"=="5" (
    set /p LLM_KEY="Google AI API key: "
    if defined LLM_KEY call :env_set "GOOGLE_API_KEY" "!LLM_KEY!"
)
if "!LLM_CHOICE!"=="6" (
    call :env_set "OLLAMA_BASE_URL" "http://127.0.0.1:11434"
    echo [OK] Ollama configured. Make sure Ollama is running before starting.
)
echo.

:: =============================================================================
:: STEP 5: Optional enrichment keys
:: =============================================================================
echo [Step 5/7] Optional enrichment keys (press Enter to skip)
echo.
set /p OTX_KEY="AlienVault OTX API key: "
if defined OTX_KEY call :env_set "OTX_API_KEY" "!OTX_KEY!"
set /p VT_KEY="VirusTotal API key: "
if defined VT_KEY call :env_set "VT_API_KEY" "!VT_KEY!"
echo.

:: =============================================================================
:: STEP 6: Start the stack
:: =============================================================================
echo [Step 6/7] Starting VoidAccess...
echo.
set /p START="Start now? [Y/n]: "
if /i "!START!"=="n" (
    echo Run manually with: run.bat
    goto DONE
)

set DOCKER_BUILDKIT=1
docker compose -f infra/docker-compose.yml --project-directory "%~dp0" --env-file "%~dp0.env" up --build -d
if errorlevel 1 (
    echo [!] Docker Compose failed. Check the output above.
    pause
    exit /b 1
)

echo.
echo Waiting for services to be ready...
set STATUS=
set /a COUNT=0
:WAIT
if !COUNT! geq 60 goto TIMEOUT
for /f "delims=" %%i in ('curl -s --max-time 5 http://localhost:8000/healthz/ready 2^>nul') do set RESPONSE=%%i
echo !RESPONSE! | findstr /c:"ready" >nul 2>&1
if not errorlevel 1 set STATUS=ready
if "!STATUS!"=="ready" goto STEP7
set /a COUNT+=1
<nul set /p=.
timeout /t 5 /nobreak >nul
goto WAIT

:TIMEOUT
echo.
echo [!] Services still starting. Continue with password setup anyway.

:: =============================================================================
:: STEP 7: Admin password
:: =============================================================================
:STEP7
echo.
echo [Step 7/7] Set admin password
echo.
set /p ADMIN_EMAIL="Admin email [admin@voidaccess.tech]: "
if not defined ADMIN_EMAIL set ADMIN_EMAIL=admin@voidaccess.tech

:PWD_LOOP
set /p ADMIN_PASS="Admin password (min 8 chars, letters + numbers): "
if not defined ADMIN_PASS goto PWD_LOOP

!PYTHON! -c "p='!ADMIN_PASS!'; exit(0 if len(p)>=8 and any(c.isalpha() for c in p) and any(c.isdigit() for c in p) else 1)" 2>nul
if errorlevel 1 (
    echo [!] Password must be at least 8 characters with letters and numbers.
    goto PWD_LOOP
)

set /p ADMIN_CONFIRM="Confirm password: "
if "!ADMIN_PASS!" neq "!ADMIN_CONFIRM!" (
    echo [!] Passwords do not match.
    goto PWD_LOOP
)

for /f "delims=" %%i in ('docker compose -f infra/docker-compose.yml exec -T fastapi !PYTHON! -c "from passlib.context import CryptContext; ctx=CryptContext(schemes=[\"bcrypt\"]); print(ctx.hash(\"!ADMIN_PASS!\"))" 2^>nul') do set HASH=%%i
if defined HASH (
    docker compose -f infra/docker-compose.yml exec -T postgres psql -U voidaccess -d voidaccess -c "UPDATE users SET hashed_password='!HASH!', must_reset_password=false, email='!ADMIN_EMAIL!' WHERE email='admin@voidaccess.tech' OR email='!ADMIN_EMAIL!';" >nul 2>&1
    echo [OK] Admin password set.
) else (
    echo [!] Could not set password automatically. Log in and change it via Settings.
)

:: =============================================================================
:: Done
:: =============================================================================
:DONE
echo.
echo  +==========================================+
echo  ^|       VoidAccess is ready!              ^|
echo  +==========================================+
echo  ^|  Web UI:   http://localhost:3001        ^|
echo  ^|  API:      http://localhost:8000        ^|
echo  ^|  API docs: http://localhost:8000/docs   ^|
echo  +==========================================+
echo  ^|  Next time just run: run.bat            ^|
echo  +==========================================+
echo.
pause
exit /b 0

:: =============================================================================
:: Subroutine: set or update a key=value line in .env
:: =============================================================================
:env_set
set "_KEY=%~1"
set "_VAL=%~2"
set "_ENV=%~dp0.env"
set "_TMP=%~dp0.env.tmp"

if not exist "!_ENV!" type nul > "!_ENV!"

:: Check if key already exists
findstr /b "!_KEY!=" "!_ENV!" >nul 2>&1
if not errorlevel 1 (
    :: Replace existing line
    (for /f "delims=" %%L in ('type "!_ENV!"') do (
        set "LINE=%%L"
        echo !LINE! | findstr /b "!_KEY!=" >nul 2>&1
        if not errorlevel 1 (
            echo !_KEY!=!_VAL!
        ) else (
            echo %%L
        )
    )) > "!_TMP!"
    move /y "!_TMP!" "!_ENV!" >nul
) else (
    :: Append new line
    echo !_KEY!=!_VAL! >> "!_ENV!"
)
exit /b 0
