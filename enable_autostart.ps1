$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent $MyInvocation.MyCommand.Path
$startup = [Environment]::GetFolderPath('Startup')
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut((Join-Path $startup 'StarStack Cascade Monitor.lnk'))
$shortcut.TargetPath = (Join-Path $project 'publish\StarStack-Cascade-Monitor.exe')
$shortcut.WorkingDirectory = $project
$shortcut.Description = 'StarStack Cascade Monitor'
$shortcut.Save()
Write-Host 'Автозапуск включен.'
