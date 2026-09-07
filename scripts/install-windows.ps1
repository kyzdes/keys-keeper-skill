#Requires -Version 5.1
<#
Installs Keys Keeper for the current Windows user and opens Settings.
No vault contents, connection codes or credential values are read by this script.
#>
[CmdletBinding()]
param(
    [string]$Source = 'https://github.com/kyzdes/keys-keeper-skill/archive/refs/heads/codex/personal-vps-sync.zip',
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'KeysKeeper'),
    [switch]$NoLaunch,
    [switch]$NoPathUpdate
)
$ErrorActionPreference = 'Stop'

function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Keys Keeper installation step failed ($LASTEXITCODE)." }
}

function Find-Python {
    foreach ($command in @('py', 'python')) {
        $candidate = Get-Command $command -ErrorAction SilentlyContinue
        if ($candidate -and $candidate.Source -notlike '*\Microsoft\WindowsApps\*') {
            $arguments = @('-c', 'import sys; assert sys.version_info >= (3, 10); print(sys.executable)')
            if ($command -eq 'py') { $arguments = @('-3') + $arguments }
            try { $found = @(& $command @arguments 2>$null) } catch { continue }
            if ($LASTEXITCODE -eq 0 -and $found -and (Test-Path $found[-1])) { return [string]$found[-1] }
        }
    }
    return $null
}

$pythonExe = Find-Python
if (-not $pythonExe) {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw 'Install Python 3.10 or newer from python.org, then run this installer again.'
    }
    Invoke-Checked 'winget' @('install', '--id', 'Python.Python.3.13', '--exact', '--scope', 'user', '--accept-package-agreements', '--accept-source-agreements')
    $pythonExe = Join-Path $env:LOCALAPPDATA 'Programs\Python\Python313\python.exe'
    if (-not (Test-Path $pythonExe)) { throw 'Python is installed. Reopen PowerShell and run this installer again.' }
}

$venv = Join-Path $InstallRoot 'venv'
$venvPython = Join-Path $venv 'Scripts\python.exe'
if (-not (Test-Path $venvPython)) { Invoke-Checked $pythonExe @('-m', 'venv', $venv) }
Invoke-Checked $venvPython @('-m', 'pip', 'install', '--upgrade', $Source)
$scripts = Join-Path $InstallRoot 'bin'
New-Item -ItemType Directory -Force -Path $scripts | Out-Null
# The pip-generated launcher embeds the absolute venv interpreter path and
# supports Unicode Windows usernames without a cmd.exe encoding workaround.
Copy-Item -Path (Join-Path $venv 'Scripts\keys.exe') -Destination (Join-Path $scripts 'keys.exe') -Force
if (-not $NoPathUpdate) {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $parts = @($userPath -split ';' | Where-Object { $_ })
    if ($parts -notcontains $scripts) {
        [Environment]::SetEnvironmentVariable('Path', ((@($scripts) + $parts) -join ';'), 'User')
    }
    $env:Path = "$scripts;$env:Path"
}
Invoke-Checked $venvPython @('-m', 'keys_keeper', 'app', 'install', '--force')
Invoke-Checked $venvPython @('-m', 'keys_keeper', 'devices', 'status')
Write-Host 'Keys Keeper is installed. Open Settings -> My computers and paste the connection code from your main computer.'
if (-not $NoLaunch) {
    Start-Process -FilePath $venvPython -ArgumentList @('-m', 'keys_keeper', 'serve') -WindowStyle Hidden
}
