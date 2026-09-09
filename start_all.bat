@echo off
setlocal
cd /d "%~dp0"

title CyberMind AI - Startup Launcher

echo ==============================================================================
echo              CyberMind AI - SOC Platform Startup Launcher
echo              Security Engineering Portfolio Project v3.0
echo ==============================================================================
echo.

echo [1/4] Checking Node.js environment...
where node >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Node.js not found in PATH!
    echo Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)

echo [2/4] Checking environment configuration...
if not exist "server\.env" (
    if exist "server\.env.example" (
        echo [INFO] server\.env not found. Copying from server\.env.example...
        copy "server\.env.example" "server\.env" >nul
        echo [OK] server\.env created successfully.
    )
)

echo [3/4] Checking project dependencies...
if not exist "node_modules\" (
    echo [INSTALL] Installing frontend dependencies...
    call npm install
)

if not exist "server\node_modules\" (
    echo [INSTALL] Installing backend dependencies...
    call npm --prefix server install
)

echo [4/4] Starting services...
echo.
echo [START] Launching Backend Telemetry Engine on Port 5000...
start "CyberMind Backend - Port 5000" /d "%~dp0server" cmd /k npm run dev

echo [WAIT] Waiting 3 seconds for backend to initialize...
ping 127.0.0.1 -n 4 >nul

echo [START] Launching Frontend Dashboard on Port 3000...
start "CyberMind Frontend - Port 3000" /d "%~dp0" cmd /k npm run dev

echo.
echo ==============================================================================
echo [SUCCESS] Both services have been launched in separate windows!
echo.
echo   Frontend Dashboard : http://localhost:3000
echo   Backend REST API   : http://localhost:5000/api
echo   Telemetry Stream   : ws://localhost:5000/ws/telemetry
echo   Prometheus Metrics : http://localhost:5000/metrics
echo.
echo   Tips:
echo   - Your default browser will open http://localhost:3000 automatically.
echo   - You can switch roles (Admin/Analyst/Viewer) in the top-right corner.
echo   - To stop the services, simply close the Backend and Frontend windows.
echo ==============================================================================
echo.
pause
