@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title ARTEX-IOT Installer

echo ============================================================
echo    ARTEX-IOT  -  Local install (build from source and run)
echo ============================================================
echo.
echo This will: check Go and Node, configure the PostgreSQL
echo connection, build the single binary with the embedded web UI,
echo and start ARTEX at http://localhost:8787
echo.
echo Requirements: Go ^>= 1.26, Node.js (npm), a reachable PostgreSQL,
echo and an internet connection for the first build.
echo.
pause
echo.

set "NEED_REOPEN="

REM ---------- Step 1/6: Go ----------
echo [1/6] Checking Go toolchain...
where go >nul 2>&1
if not errorlevel 1 (
    for /f "delims=" %%v in ('go version 2^>nul') do echo       found: %%v
) else (
    echo       Go not found.
    where winget >nul 2>&1
    if errorlevel 1 (
        echo       [x] Please install Go manually then re-run: https://go.dev/dl/
        pause
        exit /b 1
    )
    set "YN=Y"
    set /p "YN=      Install Go via winget now? (Y/N) [Y]: "
    if /i "!YN!"=="N" (
        echo       [x] Go is required. Install it then re-run install.bat.
        pause
        exit /b 1
    )
    winget install -e --id GoLang.Go --accept-source-agreements --accept-package-agreements
    set "NEED_REOPEN=1"
)

REM ---------- Step 2/6: Node.js / npm ----------
echo [2/6] Checking Node.js / npm...
where npm >nul 2>&1
if not errorlevel 1 (
    for /f "delims=" %%v in ('node --version 2^>nul') do echo       found: Node %%v
) else (
    echo       Node.js / npm not found.
    where winget >nul 2>&1
    if errorlevel 1 (
        echo       [x] Please install Node.js manually then re-run: https://nodejs.org/
        pause
        exit /b 1
    )
    set "YN=Y"
    set /p "YN=      Install Node.js via winget now? (Y/N) [Y]: "
    if /i "!YN!"=="N" (
        echo       [x] Node.js is required. Install it then re-run install.bat.
        pause
        exit /b 1
    )
    winget install -e --id OpenJS.NodeJS.LTS --accept-source-agreements --accept-package-agreements
    set "NEED_REOPEN=1"
)

REM A freshly winget-installed tool is not on PATH in THIS window yet.
if defined NEED_REOPEN (
    echo.
    echo [!] A prerequisite was just installed. Windows needs a new terminal
    echo     to see it on PATH.
    echo     ^>^> Please CLOSE this window and double-click install.bat again.
    echo.
    pause
    exit /b 0
)

REM ---------- Step 3/6: database ----------
echo.
echo [3/6] PostgreSQL connection
echo       ARTEX needs a running PostgreSQL. The backend creates the
echo       database and tables itself on first start (the DB user needs
echo       permission to create a database, or create it beforehand).
echo       No PostgreSQL yet? Install it and start the service first:
echo         winget install -e --id PostgreSQL.PostgreSQL
echo         or https://www.postgresql.org/download/windows/
echo.
set "DB_HOST=127.0.0.1"
set "DB_PORT=5432"
set "DB_USER=artex"
set "DB_PASS="
set "DB_NAME=artex"
set "DB_SSL=disable"
set /p "DB_HOST=      host [127.0.0.1]: "
set /p "DB_PORT=      port [5432]: "
set /p "DB_USER=      user [artex]: "
set /p "DB_PASS=      password: "
set /p "DB_NAME=      dbname [artex]: "
set /p "DB_SSL=      sslmode (disable/require) [disable]: "

REM ---------- Step 4/6: config.json ----------
echo.
echo [4/6] Writing config.json...
if exist config.json (
    set "OW=N"
    set /p "OW=      config.json already exists. Overwrite? (Y/N) [N]: "
    if /i not "!OW!"=="Y" (
        echo       keeping existing config.json
        goto after_config
    )
)
>  config.json echo {
>> config.json echo   "database": {
>> config.json echo     "host": "!DB_HOST!",
>> config.json echo     "port": !DB_PORT!,
>> config.json echo     "user": "!DB_USER!",
>> config.json echo     "password": "!DB_PASS!",
>> config.json echo     "dbname": "!DB_NAME!",
>> config.json echo     "sslmode": "!DB_SSL!"
>> config.json echo   }
>> config.json echo }
echo       config.json written. (If the password contains ^& ^< ^> ^| %% characters,
echo       open config.json and fix that value by hand.)
:after_config

REM ---------- Step 5/6: build embedded frontend ----------
echo.
echo [5/6] Building the web UI (first run downloads npm deps, can take minutes)...
pushd web
call npm ci
if errorlevel 1 (
    popd
    echo [x] "npm ci" failed. Check your Node.js install and network.
    pause
    exit /b 1
)
REM Set the export flag in the environment (the npm script form "NEXT_EXPORT=1 next build"
REM does not work in cmd.exe), then run the plain build.
set "NEXT_EXPORT=1"
call npm run build
if errorlevel 1 (
    popd
    echo [x] Frontend build failed.
    pause
    exit /b 1
)
popd
if exist "server\webui\dist" rmdir /s /q "server\webui\dist"
mkdir "server\webui\dist"
xcopy /e /i /y /q "web\out\*" "server\webui\dist\" >nul
if errorlevel 1 (
    echo [x] Failed to copy the exported UI into server\webui\dist.
    pause
    exit /b 1
)
echo       web UI embedded.

REM ---------- Step 6/6: build backend ----------
echo.
echo [6/6] Compiling the backend into artex.exe (first build downloads Go modules)...
set "CGO_ENABLED=0"
go build -tags embedui -o artex.exe ".\cmd\artex"
if errorlevel 1 (
    echo [x] "go build" failed.
    pause
    exit /b 1
)
echo       built: artex.exe

REM ---------- launch ----------
echo.
echo ============================================================
echo   Build complete. Starting ARTEX...
echo ============================================================
start "ARTEX-IOT" cmd /c start.bat
echo [*] Waiting for http://localhost:8787 to come up...
set /a tries=0
:waitloop
curl -s -o nul http://localhost:8787/api/health
if not errorlevel 1 goto ready
set /a tries+=1
if !tries! gtr 60 goto timeout
ping -n 3 127.0.0.1 >nul 2>&1
goto waitloop

:ready
start "" http://localhost:8787
echo.
echo [+] ARTEX is running:  http://localhost:8787
echo     First visit goes to /setup to set the admin password.
goto done

:timeout
echo.
echo [!] Timed out waiting for the server. Look at the "ARTEX-IOT" window
echo     for errors (most often the PostgreSQL connection in config.json).
echo     Once it prints "listening", open http://localhost:8787 manually.

:done
echo.
echo   Stop ARTEX:   close the "ARTEX-IOT" window.
echo   Start again:  double-click start.bat
echo   Rebuild:      run install.bat again (choose to overwrite config if asked)
echo.
pause
exit /b 0
