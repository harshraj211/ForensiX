[CmdletBinding()]
param(
    [ValidatePattern("^[0-9]+(?:\.[0-9]+){1,3}$")]
    [string]$Version = "7.2",
    [string]$Destination
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $Destination) {
    $Destination = Join-Path $projectRoot "tools\testdisk"
}

# CGSecurity distributes TestDisk and PhotoRec as a portable archive.  We keep
# the executable out of Git and rely on the SHA-256 printed below for the
# per-session pin enforced by ForensiX.
$assetName = "testdisk-$Version.win64.zip"
$downloadUrl = "https://www.cgsecurity.org/$assetName"
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("forensix-testdisk-" + [guid]::NewGuid().ToString("N"))
$archivePath = Join-Path $temporaryRoot $assetName
$extractPath = Join-Path $temporaryRoot "extracted"

try {
    New-Item -ItemType Directory -Path $temporaryRoot -Force | Out-Null
    Write-Host "Downloading official CGSecurity TestDisk/PhotoRec $Version for Windows..."
    Invoke-WebRequest -Uri $downloadUrl -OutFile $archivePath
    Expand-Archive -LiteralPath $archivePath -DestinationPath $extractPath -Force

    $photoRecExecutable = Get-ChildItem -Path $extractPath -Filter "photorec_win.exe" -File -Recurse |
        Select-Object -First 1
    if ($null -eq $photoRecExecutable) {
        throw "The official TestDisk archive did not contain photorec_win.exe."
    }

    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    Copy-Item -Path (Join-Path $photoRecExecutable.DirectoryName "*") -Destination $Destination -Recurse -Force
    $installedPath = Join-Path $Destination "photorec_win.exe"
    if (-not (Test-Path -LiteralPath $installedPath -PathType Leaf)) {
        throw "PhotoRec was not installed to the expected destination."
    }

    $digest = (Get-FileHash -LiteralPath $installedPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host "PhotoRec installed: $installedPath"
    Write-Host "SHA-256: $digest"
    Write-Host "Start ForensiX normally; the launcher will discover and pin this executable for its session."
    Write-Host "Only run recovery against a verified raw ext4/F2FS Evidence Twin working copy."
} finally {
    Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
}
