[CmdletBinding()]
param(
    [ValidatePattern("^[0-9]+(?:\.[0-9]+){1,3}$")]
    [string]$Version = "4.1",
    [string]$Destination
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $Destination) {
    $Destination = Join-Path $projectRoot "tools\scrcpy"
}

$assetName = "scrcpy-win64-v$Version.zip"
$downloadUrl = "https://github.com/Genymobile/scrcpy/releases/download/v$Version/$assetName"
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("forensix-scrcpy-" + [guid]::NewGuid().ToString("N"))
$archivePath = Join-Path $temporaryRoot $assetName
$extractPath = Join-Path $temporaryRoot "extracted"

try {
    New-Item -ItemType Directory -Path $temporaryRoot -Force | Out-Null
    Write-Host "Downloading official Genymobile scrcpy release v$Version..."
    Invoke-WebRequest -Uri $downloadUrl -OutFile $archivePath
    Expand-Archive -LiteralPath $archivePath -DestinationPath $extractPath -Force

    $scrcpyExecutable = Get-ChildItem -Path $extractPath -Filter "scrcpy.exe" -File -Recurse |
        Select-Object -First 1
    if ($null -eq $scrcpyExecutable) {
        throw "The official archive did not contain scrcpy.exe."
    }

    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    Copy-Item -Path (Join-Path $scrcpyExecutable.DirectoryName "*") -Destination $Destination -Recurse -Force
    $installedPath = Join-Path $Destination "scrcpy.exe"
    $versionOutput = & $installedPath --version 2>&1
    if ($LASTEXITCODE -ne 0 -or -not ($versionOutput -match "scrcpy\s+$([regex]::Escape($Version))")) {
        throw "The installed executable failed its version validation."
    }
    $digest = (Get-FileHash -LiteralPath $installedPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host "scrcpy installed: $installedPath"
    Write-Host "SHA-256: $digest"
    Write-Host "Start ForensiX normally; the launcher will discover and pin this executable for its session."
} finally {
    Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
}
