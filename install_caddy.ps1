$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$tools = Join-Path $root 'tools'
$target = Join-Path $tools 'caddy.exe'

New-Item -ItemType Directory -Path $tools -Force | Out-Null
Write-Host 'Downloading the official Caddy Windows amd64 build...'
Invoke-WebRequest -Uri 'https://caddyserver.com/api/download?os=windows&arch=amd64' -OutFile $target
& $target version
Write-Host "Installed: $target"
