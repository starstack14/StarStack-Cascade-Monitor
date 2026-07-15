$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$keys = Join-Path $root 'keys'
$privateKey = Join-Path $keys 'router_monitor_ed25519'

New-Item -ItemType Directory -Path $keys -Force | Out-Null
if (Test-Path $privateKey) {
    throw "Key already exists: $privateKey"
}

ssh-keygen.exe -t ed25519 -a 64 -f $privateKey -C 'starstack-cascade-monitor'
Write-Host 'Copy the following public key to /etc/dropbear/authorized_keys on OpenWrt:'
Get-Content ($privateKey + '.pub')
