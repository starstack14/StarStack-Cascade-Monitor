$shortcut = Join-Path ([Environment]::GetFolderPath('Startup')) 'StarStack Cascade Monitor.lnk'
Remove-Item -LiteralPath $shortcut -Force -ErrorAction SilentlyContinue
Write-Host 'Автозапуск отключен.'
