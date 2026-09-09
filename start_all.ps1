# CyberMind AI - PowerShell Startup Launcher
# Security Engineering Portfolio Project v3.0

$Host.UI.RawUI.WindowTitle = "CyberMind AI - Platform Launcher"

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "             CyberMind AI - SOC Platform Startup Launcher (PowerShell)        " -ForegroundColor Cyan
Write-Host "             Security Engineering Portfolio Project v3.0                     " -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check Node.js
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Node.js is not found in PATH!" -ForegroundColor Red
    Write-Host "Please install Node.js from https://nodejs.org/" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# 2. Check server/.env
$repoRoot = $PSScriptRoot
$serverEnv = Join-Path $repoRoot "server\.env"
$serverEnvExample = Join-Path $repoRoot "server\.env.example"

if (-not (Test-Path $serverEnv)) {
    if (Test-Path $serverEnvExample) {
        Write-Host "[SETUP] Creating server/.env from template..." -ForegroundColor Yellow
        Copy-Item $serverEnvExample $serverEnv
        Write-Host "[OK] server/.env created." -ForegroundColor Green
    }
}

# 3. Check node_modules
if (-not (Test-Path (Join-Path $repoRoot "node_modules"))) {
    Write-Host "[INSTALL] Installing frontend dependencies..." -ForegroundColor Yellow
    npm install
}

if (-not (Test-Path (Join-Path $repoRoot "server\node_modules"))) {
    Write-Host "[INSTALL] Installing backend dependencies..." -ForegroundColor Yellow
    npm --prefix server install
}

# 4. Launch Backend & Frontend in separate windows
Write-Host "[START] Launching Backend Telemetry Engine on Port 5000..." -ForegroundColor Green
Start-Process cmd -ArgumentList "/k npm run dev" -WorkingDirectory (Join-Path $repoRoot "server")

Write-Host "[WAIT] Waiting 3 seconds for backend to initialize..." -ForegroundColor DarkGray
Start-Sleep -Seconds 3

Write-Host "[START] Launching Frontend Dashboard on Port 3000..." -ForegroundColor Green
Start-Process cmd -ArgumentList "/k npm run dev" -WorkingDirectory $repoRoot

Write-Host ""
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "[SUCCESS] Both services have been launched in separate windows!" -ForegroundColor Green
Write-Host ""
Write-Host "  Frontend Dashboard : http://localhost:3000" -ForegroundColor White
Write-Host "  Backend REST API   : http://localhost:5000/api" -ForegroundColor White
Write-Host "  Telemetry Stream   : ws://localhost:5000/ws/telemetry" -ForegroundColor White
Write-Host "  Prometheus Metrics : http://localhost:5000/metrics" -ForegroundColor White
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Tips: Close the popped-up command windows to stop the services." -ForegroundColor DarkGray
Write-Host ""
