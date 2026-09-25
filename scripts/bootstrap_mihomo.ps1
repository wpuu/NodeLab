#requires -Version 5.1
<#
.SYNOPSIS
  Downloads Mihomo v1.19.31 for Windows amd64, verifies SHA256, extracts to
  tools/mihomo/, and runs `mihomo.exe -v`. Aborts on any failure.
#>

$ErrorActionPreference = "Stop"

$Version   = "v1.19.31"
$AssetName = "mihomo-windows-amd64-compatible-$Version.zip"
$Url       = "https://github.com/MetaCubeX/mihomo/releases/download/$Version/$AssetName"
$Sha256    = "93d14e9a13b49b2f2d256202d02cc8d14a7c4695edf084cae0f941986bc9c218"

$RepoRoot  = Split-Path -Parent $PSScriptRoot
$ToolsDir  = Join-Path $RepoRoot "tools"
$MihomoDir = Join-Path $ToolsDir "mihomo"
$TmpDir    = Join-Path $Env:TEMP "nodelab-mihomo-bootstrap"
$ZipPath   = Join-Path $TmpDir $AssetName

Write-Host "NodeLab bootstrap: Mihomo $Version"
Write-Host "  asset : $AssetName"
Write-Host "  sha256: $Sha256"

# 1. temp dir
if (Test-Path $TmpDir) { Remove-Item -Recurse -Force $TmpDir }
New-Item -ItemType Directory -Path $TmpDir | Out-Null

# 2. download
Write-Host "Downloading $Url ..."
$ProgressPreference = "SilentlyContinue"
Invoke-WebRequest -Uri $Url -OutFile $ZipPath -UseBasicParsing

if (-not (Test-Path $ZipPath)) {
    Write-Host "FAIL: download did not produce $ZipPath"
    exit 1
}

# 3. SHA256 check
Write-Host "Computing SHA256 ..."
$Hash = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($Hash -ne $Sha256) {
    Write-Host "FAIL: SHA256 mismatch"
    Write-Host "  expected: $Sha256"
    Write-Host "  got     : $Hash"
    exit 1
}
Write-Host "SHA256 OK"

# 4. extract into tools/mihomo
if (Test-Path $MihomoDir) { Remove-Item -Recurse -Force $MihomoDir }
New-Item -ItemType Directory -Path $MihomoDir | Out-Null
Expand-Archive -Path $ZipPath -DestinationPath $MihomoDir -Force

# 5. locate mihomo.exe (asset zip ships mihomo-windows-amd64-compatible.exe; rename it)
$Exe = Get-ChildItem -Path $MihomoDir -Filter "mihomo.exe" -Recurse | Select-Object -First 1
if ($null -eq $Exe) {
    $Renamed = Get-ChildItem -Path $MihomoDir -Filter "mihomo-windows-amd64*.exe" -Recurse | Select-Object -First 1
    if ($null -eq $Renamed) {
        Write-Host "FAIL: mihomo.exe not found under $MihomoDir"
        exit 1
    }
    Rename-Item -Path $Renamed.FullName -NewName "mihomo.exe"
    $Exe = Get-ChildItem -Path $MihomoDir -Filter "mihomo.exe" -Recurse | Select-Object -First 1
}
Write-Host "Found: $($Exe.FullName)"

# 6. run version check
Write-Host "Running mihomo -v ..."
& $Exe.FullName -v
if ($LASTEXITCODE -ne 0) {
    Write-Host "FAIL: mihomo -v exited $LASTEXITCODE"
    exit 1
}

# 7. cleanup zip
Remove-Item $ZipPath -Force
Write-Host "Bootstrap PASS: $Version"
exit 0
