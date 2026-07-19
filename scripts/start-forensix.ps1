[CmdletBinding()]
param(
    [string]$AdbPath,
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

$pnpmCommand = Get-Command pnpm.cmd -ErrorAction SilentlyContinue
if (-not $pnpmCommand) {
    throw "pnpm.cmd was not found on PATH. Install pnpm 11 or newer."
}

function Test-ListeningPort([int]$Port) {
    return [bool](Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)
}

if (-not (Test-ListeningPort $ApiPort)) {
    $env:FORENSIX_ADB_MODE = "system"
    $env:FORENSIX_ADB_PATH = $AdbPath
    $env:FORENSIX_API_PORT = [string]$ApiPort
    Start-Process -FilePath $pythonPath `
        -ArgumentList "-m uvicorn forensix_api.main:app --host 127.0.0.1 --port $ApiPort" `
        -WorkingDirectory $projectRoot -WindowStyle Hidden | Out-Null
}

if (-not (Test-ListeningPort $WebPort)) {
    Start-Process -FilePath $pnpmCommand.Source `
        -ArgumentList "--dir apps/web dev --host 127.0.0.1 --port $WebPort" `
        -WorkingDirectory $projectRoot -WindowStyle Hidden | Out-Null
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

$deviceLines = & $AdbPath devices -l 2>&1
$authorizedCount = @($deviceLines | Where-Object { $_ -match "\sdevice(?:\s|$)" }).Count
$webUrl = "http://127.0.0.1:$WebPort/devices"

Write-Host "ForensiX is ready: $webUrl"
Write-Host "ADB: $AdbPath"
Write-Host "Authorized Android transports: $authorizedCount"

if (-not $NoBrowser) {
    Start-Process $webUrl | Out-Null
}
