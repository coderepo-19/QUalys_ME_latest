# Environment Setup Script for Qualys Integration (Moved to scripts/Slave)

# 1. Determine Project Root (two levels up)
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$projectRoot = Split-Path -Parent (Split-Path -Parent $scriptDir)

# 2. Check for Python
if (!(Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "Python is not installed or not in PATH. Please install Python 3.9+ and try again."
    exit 1
}

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "      Qualys-ME Environment Setup (Windows)      " -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

# 3. Create Virtual Environment at Project Root
Set-Location $projectRoot
if (!(Test-Path ".venv")) {
    Write-Host "[1/4] Creating virtual environment (.venv) at project root..." -ForegroundColor Yellow
    python -m venv .venv
}
else {
    Write-Host "[1/4] Virtual environment (.venv) already exists." -ForegroundColor Green
}

# 4. Determine Paths (Support both PS 5.1 and PS Core)
$isWin = ($env:OS -like "*Windows*")
$pythonVenv = if ($isWin) { ".venv\Scripts\python.exe" } else { ".venv/bin/python" }

# 5. Install Requirements
Write-Host "[2/4] Upgrading pip and installing requirements..." -ForegroundColor Yellow
& $pythonVenv -m pip install --upgrade pip
& $pythonVenv -m pip install --upgrade -r requirements.txt

# 6. Setup .env file
Write-Host "[3/4] Initializing environment variables..." -ForegroundColor Yellow
$templatePath = "Config\.env_template"
$envPath = "Config\.env"

if (Test-Path $templatePath) {
    if (!(Test-Path $envPath)) {
        Copy-Item $templatePath $envPath
        Write-Host "[SUCCESS] Created Config\.env from template." -ForegroundColor Green
    }
    else {
        Write-Host "[INFO] Config\.env already exists. Skipping copy." -ForegroundColor Gray
    }
}
else {
    Write-Host "[WARN] .env_template not found in Config folder." -ForegroundColor Red
}

Write-Host "[4/4] Verifying installation..." -ForegroundColor Yellow
& $pythonVenv -m pip list

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "           Setup Completed Successfully!         " -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "To activate the environment, run:"
Write-Host "   .venv\Scripts\Activate.ps1"
Write-Host "=================================================" -ForegroundColor Cyan
