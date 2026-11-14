<#
.SYNOPSIS
  One-command demo setup: checks keys, starts the gateway (if needed), seeds a week of orders.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\seed_and_run.ps1
  powershell -ExecutionPolicy Bypass -File .\seed_and_run.ps1 -Fresh        # clean slate for the judges

.PARAMETER Fresh
  Stops the running gateway, ARCHIVES (never deletes) var\gateway.db and the audit log,
  then starts clean. Use it before the demo so history from test runs can't change outcomes.
#>
param(
    [string]$Url = "http://localhost:8000",
    [switch]$Fresh,
    [switch]$Lexical,           # skip the embedding model (keyword-only search); semantic FAISS search is the default
    [double]$Delay = 1.0
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

function Write-Step($text) { Write-Host "`n==> $text" -ForegroundColor Cyan }
function Fail($text) { Write-Host "ERROR: $text" -ForegroundColor Red; exit 1 }

function Test-Gateway {
    try { return (Invoke-WebRequest -Uri "$Url/health" -UseBasicParsing -TimeoutSec 3).StatusCode -eq 200 }
    catch { return $false }
}

# ---------------------------------------------------------------- 1. keys (values are never printed)
Write-Step "Checking API keys"
$envFile = Join-Path $PSScriptRoot ".env"
$dotenv = if (Test-Path $envFile) { Get-Content $envFile } else { @() }
foreach ($name in @("VALIO_API_KEY", "GEMINI_API_KEY")) {
    $inProcess = [bool][Environment]::GetEnvironmentVariable($name)
    $inDotenv = [bool]($dotenv | Where-Object { $_ -match "^\s*$name\s*=\s*\S+" })
    if (-not ($inProcess -or $inDotenv)) {
        Fail "$name is not set. Add '$name=...' to .env (or set `$env:$name) and run again."
    }
    $where = if ($inProcess) { "environment" } else { ".env" }
    Write-Host "  $name is set ($where)" -ForegroundColor Green
}

if (-not (Get-Command python -ErrorAction SilentlyContinue)) { Fail "python is not on PATH" }

# ---------------------------------------------------------------- 2. optional fresh start
if ($Fresh) {
    Write-Step "Fresh start: stopping the gateway and archiving old state"
    Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
        Where-Object { $_.CommandLine -like '*uvicorn src.main:app*' } |
        ForEach-Object { Write-Host "  stopping gateway process $($_.ProcessId)"; Stop-Process -Id $_.ProcessId -Force }
    Start-Sleep -Seconds 1

    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $archive = Join-Path $PSScriptRoot "var\archive"
    New-Item -ItemType Directory -Force -Path $archive | Out-Null
    foreach ($suffix in @("", "-wal", "-shm")) {          # SQLite keeps recent writes in -wal: move all three together
        $f = Join-Path $PSScriptRoot "var\gateway.db$suffix"
        if (Test-Path $f) { Move-Item $f (Join-Path $archive "gateway.$stamp.db$suffix"); Write-Host "  archived var\gateway.db$suffix" }
    }
    python -m src.audit reset --yes --reason "Fresh demo seed via seed_and_run.ps1"
    if ($LASTEXITCODE -ne 0) { Fail "audit log reset failed" }
}

# ---------------------------------------------------------------- 3. server
Write-Step "Starting the gateway"
if (Test-Gateway) {
    Write-Host "  already running at $Url" -ForegroundColor Green
} else {
    $semanticFlag = if ($Lexical) { "0" } else { "1" }
    $cmd = "`$host.UI.RawUI.WindowTitle = 'Valio Agent Gateway'; `$env:GATEWAY_SEMANTIC = '$semanticFlag'; python -m uvicorn src.main:app --port 8000"
    Start-Process powershell -WorkingDirectory $PSScriptRoot -ArgumentList "-NoExit", "-Command", $cmd
    Write-Host "  launched in a new window (logs there; Ctrl+C in that window stops it). Waiting for /health..."
    $deadline = (Get-Date).AddSeconds($(if ($Lexical) { 180 } else { 900 }))   # first semantic run embeds the catalog
    while (-not (Test-Gateway)) {
        if ((Get-Date) -gt $deadline) { Fail "gateway did not become healthy; check the server window for errors" }
        Start-Sleep -Seconds 2
    }
    Write-Host "  gateway is up" -ForegroundColor Green
}

# ---------------------------------------------------------------- 4. seed
Write-Step "Seeding a week of agent activity (watch the dashboard update live)"
python examples/seed.py --url $Url --delay $Delay
$seedExit = $LASTEXITCODE

# ---------------------------------------------------------------- 5. instructions
Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host " Dashboard:  $Url/dashboard" -ForegroundColor White
Write-Host " Login:      manager / manager123   (read-only: auditor / auditor123)"
Write-Host ""
Write-Host " Demo script for the judges:"
Write-Host "  1. Point at the KPI tiles and the 'Order decisions' chart (green / purple / red)."
Write-Host "  2. Open the drift-flagged milk order: explain the +300% DRIFT DETECTED badge."
Write-Host "  3. Approve the cleaning-chemicals order with 'Approve & Remember'."
Write-Host "  4. Click the sparkle (bottom right) and ask: 'Why was the last order rejected?'"
Write-Host "  5. Click 'Verify chain' to prove the audit trail is tamper-evident."
Write-Host "==========================================================================" -ForegroundColor Cyan
if ($seedExit -ne 0) {
    Write-Host "Note: some seeded outcomes differed from the plan (see above). Run with -Fresh for a clean slate." -ForegroundColor Yellow
}
