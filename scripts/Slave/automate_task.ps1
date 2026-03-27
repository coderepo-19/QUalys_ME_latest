# Qualys-SDP Automation Setup Script
# This script creates a Windows Scheduled Task based on settings in Config\.env

# 1. Determine Project Root (two levels up from scripts/Slave)
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$projectRoot = Split-Path -Parent (Split-Path -Parent $scriptDir)
$envPath = Join-Path $projectRoot "Config\.env"

# 2. Function to load .env variables
function Import-Env {
    param($Path)
    if (Test-Path $Path) {
        Get-Content $Path | ForEach-Object {
            # Match Name="Value" or Name='Value' or Name=Value
            if ($_ -match "^\s*([^#\s][^=]*)\s*=\s*['""]?(.*?)['""]?\s*$") {
                $name = $matches[1].Trim()
                $value = $matches[2].Trim()
                Set-Variable -Name "ENV_$name" -Value $value -Scope Script -Force
            }
        }
    }
}

# 3. Load Environment
Import-Env -Path $envPath

# 4. Define Paths & Defaults
$venvPython = Join-Path $projectRoot ".venv\Scripts\python.exe"
$masterScript = Join-Path $projectRoot "scripts\Master\Master.py"
$taskName = "Qualys-SDP-Integration"

# Read from .env or use defaults
$freq     = if ($null -ne $Script:ENV_AUTO_RUN_FREQUENCY) { $Script:ENV_AUTO_RUN_FREQUENCY } else { "Daily" }
$time     = if ($null -ne $Script:ENV_AUTO_RUN_TIME) { $Script:ENV_AUTO_RUN_TIME } else { "09:00" }
$daysRaw  = if ($null -ne $Script:ENV_AUTO_RUN_DAYS) { $Script:ENV_AUTO_RUN_DAYS } else { "Monday" }

# Parse days into array (handling comma-separated lists)
$daysArray = $daysRaw.Split(",").Trim()

# 5. Verification
if (!(Test-Path $venvPython)) {
    Write-Error "Virtual environment (.venv) not found. Please run setup_env.ps1 first."
    exit 1
}
if (!(Test-Path $masterScript)) {
    Write-Error "Master script not found at $masterScript."
    exit 1
}

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "      Qualys-ME Automation Setup (Windows)       " -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "Loading settings from Config\.env..." -ForegroundColor Gray

# 6. Create Task Trigger based on Frequency
try {
    if ($freq -eq "Weekly") {
        # DaysOfWeek expects enum array (e.g., Monday,Tuesday)
        $trigger = New-ScheduledTaskTrigger -Weekly -At $time -DaysOfWeek $daysArray
        $schedDesc = "Weekly on [$daysRaw] at $time"
    } elseif ($freq -eq "Monthly") {
        # DaysOfMonth requires int array (e.g., 1,15)
        $daysIntArray = $daysArray | ForEach-Object { [int]$_ }
        $trigger = New-ScheduledTaskTrigger -Monthly -At $time -DaysOfMonth $daysIntArray
        $schedDesc = "Monthly on Day(s) [$daysRaw] at $time"
    } else {
        $trigger = New-ScheduledTaskTrigger -Daily -At $time
        $schedDesc = "Daily at $time"
    }
} catch {
    Write-Host "-------------------------------------------------" -ForegroundColor Red
    Write-Error "Invalid Schedule Settings in .env (Freq: $freq, Time: $time, Days: $daysRaw)"
    Write-Host "For Weekly, use days like: Monday, Tuesday, etc."
    Write-Host "For Monthly, use numbers like: 1, 15, 31."
    Write-Host "-------------------------------------------------" -ForegroundColor Red
    exit 1
}

Write-Host "Target Schedule: $schedDesc" -ForegroundColor Yellow

# 7. Create Task Action
$action = New-ScheduledTaskAction -Execute $venvPython `
    -Argument """$masterScript""" `
    -WorkingDirectory $projectRoot

# 8. Create Task Settings
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew

# 9. Register Task
try {
    # Check if task already exists and remove it to update
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-Host "Updating existing task..." -ForegroundColor Gray
    }
    
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Description "Qualys to ServiceDesk Plus Integration - Automatically triggered via .env settings"
    
    Write-Host "=================================================" -ForegroundColor Cyan
    Write-Host "        [SUCCESS] Automation Scheduled!          " -ForegroundColor Green
    Write-Host "=================================================" -ForegroundColor Cyan
    Write-Host "Task Name   : $taskName"
    Write-Host "Schedule    : $schedDesc"
    Write-Host "Working Dir : $projectRoot"
    Write-Host "=================================================" -ForegroundColor Cyan
    Write-Host "You can manage this task in 'Task Scheduler' (taskschd.msc)."
} catch {
    Write-Host "-------------------------------------------------" -ForegroundColor Red
    Write-Error "CRITICAL: Access Denied. Please run PowerShell as ADMINISTRATOR to register the task."
    Write-Host "-------------------------------------------------" -ForegroundColor Red
}
