[CmdletBinding()]
param(
    [string]$AdbPath,
    [string]$ScrcpyPath,
    [ValidateRange(1024, 65535)][int]$ApiPort = 8765,
    [ValidateRange(1024, 65535)][int]$WebPort = 5173,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$pythonPath = Join-Path $projectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $pythonPath -PathType Leaf)) {
    throw "Python environment is missing. Run the README setup commands first."
}

if (-not $AdbPath) {
    $adbCommand = Get-Command adb.exe -ErrorAction SilentlyContinue
    if ($adbCommand) {
        $AdbPath = $adbCommand.Source
    } else {
        $sdkAdb = Join-Path $env:LOCALAPPDATA "Android\Sdk\platform-tools\adb.exe"
        if (Test-Path -LiteralPath $sdkAdb -PathType Leaf) {
            $AdbPath = $sdkAdb
        }
    }
}

if (-not $AdbPath -or -not (Test-Path -LiteralPath $AdbPath -PathType Leaf)) {
    throw "ADB was not found. Supply -AdbPath with the full path to adb.exe."
}
$AdbPath = (Resolve-Path -LiteralPath $AdbPath).Path
$adbVersion = & $AdbPath version 2>&1
if ($LASTEXITCODE -ne 0 -or -not ($adbVersion -match "Android Debug Bridge version")) {
    throw "The configured ADB executable did not pass the version check: $AdbPath"
}

if (-not $ScrcpyPath) {
    $scrcpyCommand = Get-Command scrcpy.exe -ErrorAction SilentlyContinue
    if ($scrcpyCommand) {
        $ScrcpyPath = $scrcpyCommand.Source
    } else {
        $localScrcpy = Join-Path $projectRoot "tools\scrcpy\scrcpy.exe"
        $programFilesScrcpy = Join-Path $env:ProgramFiles "scrcpy\scrcpy.exe"
        if (Test-Path -LiteralPath $localScrcpy -PathType Leaf) {
            $ScrcpyPath = $localScrcpy
        } elseif (Test-Path -LiteralPath $programFilesScrcpy -PathType Leaf) {
            $ScrcpyPath = $programFilesScrcpy
        }
    }
}

$scrcpyReady = $false
if ($ScrcpyPath) {
    if (-not (Test-Path -LiteralPath $ScrcpyPath -PathType Leaf)) {
        throw "The configured scrcpy executable was not found: $ScrcpyPath"
    }
    $ScrcpyPath = (Resolve-Path -LiteralPath $ScrcpyPath).Path
    $scrcpyVersion = & $ScrcpyPath --version 2>&1
    if ($LASTEXITCODE -ne 0 -or -not ($scrcpyVersion -match "scrcpy\s+[0-9]+(?:\.[0-9]+){1,3}")) {
        throw "The configured scrcpy executable did not pass the version check: $ScrcpyPath"
    }
    $env:FORENSIX_SCRCPY_PATH = $ScrcpyPath
    $env:FORENSIX_SCRCPY_EXPECTED_SHA256 = (Get-FileHash -LiteralPath $ScrcpyPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $scrcpyReady = $true
}

$pnpmCommand = Get-Command pnpm.cmd -ErrorAction SilentlyContinue
if (-not $pnpmCommand) {
    throw "pnpm.cmd was not found on PATH. Install pnpm 11 or newer."
}

function Test-ListeningPort([int]$Port) {
    return [bool](Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)
}

$logDirectory = Join-Path $projectRoot "data\logs"
New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null

if (-not (Test-ListeningPort $ApiPort)) {
    $env:FORENSIX_ADB_MODE = "system"
    $env:FORENSIX_ADB_PATH = $AdbPath
    $env:FORENSIX_API_PORT = [string]$ApiPort
    Start-Process -FilePath $pythonPath `
        -ArgumentList "-m uvicorn forensix_api.main:app --host 127.0.0.1 --port $ApiPort" `
        -WorkingDirectory $projectRoot -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $logDirectory "api.out.log") `
        -RedirectStandardError (Join-Path $logDirectory "api.err.log") | Out-Null
}

if (-not (Test-ListeningPort $WebPort)) {
    Start-Process -FilePath $pnpmCommand.Source `
        -ArgumentList "--dir apps/web dev --host 127.0.0.1 --port $WebPort" `
        -WorkingDirectory $projectRoot -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $logDirectory "web.out.log") `
        -RedirectStandardError (Join-Path $logDirectory "web.err.log") | Out-Null
}

$deadline = (Get-Date).AddSeconds(20)
do {
    Start-Sleep -Milliseconds 250
    $apiReady = Test-ListeningPort $ApiPort
    $webReady = Test-ListeningPort $WebPort
} until (($apiReady -and $webReady) -or (Get-Date) -ge $deadline)

if (-not $apiReady -or -not $webReady) {
    throw "ForensiX did not become ready within 20 seconds. Check the terminal and runtime logs."
}

$previousPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$deviceLines = & $AdbPath devices -l 2>&1
$deviceListExitCode = $LASTEXITCODE
$ErrorActionPreference = $previousPreference
if ($deviceListExitCode -ne 0) {
    Write-Warning "ADB device listing failed after startup; use scripts\Test-ForensiX.ps1 for diagnostics."
}
$authorizedCount = @($deviceLines | Where-Object { $_ -match "\sdevice(?:\s|$)" }).Count
$webUrl = "http://127.0.0.1:$WebPort/devices"

Write-Host "ForensiX is ready: $webUrl"
Write-Host "ADB: $AdbPath"
Write-Host "Authorized Android transports: $authorizedCount"
if ($scrcpyReady) {
    Write-Host "scrcpy: $ScrcpyPath"
    Write-Host "Live mirror: ready (read-only by default; control needs an acknowledgement)"
} else {
    Write-Warning "scrcpy was not found. Run .\scripts\install-scrcpy.ps1 to enable live mirror and control."
}
Write-Host "Runtime logs: $logDirectory"

if (-not $NoBrowser) {
    Start-Process $webUrl | Out-Null
}
