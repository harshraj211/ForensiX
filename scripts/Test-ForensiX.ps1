[CmdletBinding()]
param([string]$AdbPath)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$failures = [System.Collections.Generic.List[string]]::new()

function Write-Check([string]$Name, [bool]$Passed, [string]$Detail) {
    $label = if ($Passed) { "PASS" } else { "FAIL" }
    $color = if ($Passed) { "Green" } else { "Red" }
    Write-Host "[$label] $Name - $Detail" -ForegroundColor $color
    if (-not $Passed) { $failures.Add($Name) }
}

$python = Join-Path $projectRoot ".venv\Scripts\python.exe"
Write-Check "Python environment" (Test-Path -LiteralPath $python -PathType Leaf) $python
$pnpm = Get-Command pnpm.cmd -ErrorAction SilentlyContinue
Write-Check "pnpm" ([bool]$pnpm) $(if ($pnpm) { $pnpm.Source } else { "not found on PATH" })

if (-not $AdbPath) {
    $adb = Get-Command adb.exe -ErrorAction SilentlyContinue
    if ($adb) { $AdbPath = $adb.Source }
    if (-not $AdbPath) {
        $candidate = Join-Path $env:LOCALAPPDATA "Android\Sdk\platform-tools\adb.exe"
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { $AdbPath = $candidate }
    }
}
$adbExists = $AdbPath -and (Test-Path -LiteralPath $AdbPath -PathType Leaf)
Write-Check "ADB executable" ([bool]$adbExists) $(if ($AdbPath) { $AdbPath } else { "not found" })
if ($adbExists) {
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $version = & $AdbPath version 2>&1
    $versionExitCode = $LASTEXITCODE
    $devices = & $AdbPath devices -l 2>&1
    $devicesExitCode = $LASTEXITCODE
    $ErrorActionPreference = $previousPreference
    Write-Check "ADB version command" ($versionExitCode -eq 0) (($version | Select-Object -First 1) -join "")
    Write-Check "ADB device-list command" ($devicesExitCode -eq 0) "bounded transport query completed"
    $authorized = @($devices | Where-Object { $_ -match "\sdevice(?:\s|$)" }).Count
    $unauthorized = @($devices | Where-Object { $_ -match "\sunauthorized(?:\s|$)" }).Count
    $offline = @($devices | Where-Object { $_ -match "\soffline(?:\s|$)" }).Count
    Write-Host "[INFO] Android transports - authorized=$authorized unauthorized=$unauthorized offline=$offline"
    if (($authorized + $unauthorized + $offline) -eq 0) {
        Write-Host "[GUIDANCE] Use a data-capable cable and verify the OEM driver in Device Manager." -ForegroundColor Yellow
    }
}

$drive = Get-Item $projectRoot
$freeGiB = [math]::Round($drive.PSDrive.Free / 1GB, 1)
Write-Check "Free disk space" ($drive.PSDrive.Free -ge 5GB) "$freeGiB GiB free (5 GiB minimum for development)"
Write-Host "[INFO] ForensiX binds to loopback only (127.0.0.1)."

if ($failures.Count -gt 0) {
    Write-Host "Diagnostics failed: $($failures -join ', ')" -ForegroundColor Red
    exit 1
}
Write-Host "ForensiX workstation prerequisites passed." -ForegroundColor Green
