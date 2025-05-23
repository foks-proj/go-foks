$ErrorActionPreference = 'Stop'
$toolsDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Write-Host "Stopping foks..."
& "$toolsDir\foks.exe" 'ctl' 'stop'