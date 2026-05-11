# Install the keys-keeper skill into %USERPROFILE%\.claude\skills\
#
# Usage:
#   .\scripts\install_skill.ps1            # refuses to overwrite an existing install
#   .\scripts\install_skill.ps1 -Force     # overwrite

[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

$Source = Join-Path (Split-Path -Parent $PSScriptRoot) 'skills\keys-keeper'
$Dest   = Join-Path $env:USERPROFILE '.claude\skills\keys-keeper'

if (-not (Test-Path $Source)) {
    Write-Error "skill source not found: $Source"
    exit 1
}

if (Test-Path $Dest) {
    if (-not $Force) {
        Write-Error "$Dest already exists; pass -Force to overwrite"
        exit 1
    }
    Remove-Item -Recurse -Force $Dest
}

$DestParent = Split-Path -Parent $Dest
if (-not (Test-Path $DestParent)) {
    New-Item -ItemType Directory -Path $DestParent -Force | Out-Null
}

Copy-Item -Recurse $Source $Dest
Write-Host "installed skill at $Dest"
