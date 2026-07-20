# StarStack Cascade Monitor · .NET WPF

Новая Windows-версия мониторинга каскада на C# / .NET 8 / WPF. Стабильная Python-версия продолжает жить в ветке `main`; эта ветка полностью собирается только из .NET-проекта.

## Что уже работает

- Neon Glass WPF-интерфейс;
- живой статус NX31 через SSH.NET;
- uptime, Load Average, RAM и состояние sing-box;
- встроенный SSH-терминал NX31;
- запуск отдельной вкладки Windows Terminal;
- SSH-ключ не хранится в Git и не публикуется через web-панель.

## Структура

```text
src/StarStack.CascadeMonitor/
  MainWindow.xaml              основной WPF-интерфейс
  RouterMonitorService.cs      мониторинг NX31 по SSH
  SshTerminalWindow.xaml       встроенный SSH-терминал
  StarStack.CascadeMonitor.csproj
assets/                        иконки
keys/                          локальный SSH-ключ (не коммитится)
```

## Локальная сборка

```powershell
dotnet restore src\StarStack.CascadeMonitor\StarStack.CascadeMonitor.csproj
dotnet build src\StarStack.CascadeMonitor\StarStack.CascadeMonitor.csproj --configuration Release
dotnet publish src\StarStack.CascadeMonitor\StarStack.CascadeMonitor.csproj --configuration Release --runtime win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true --output publish
```

EXE появится в `publish\StarStack-Cascade-Monitor.exe`.

Путь к ключу по умолчанию: `keys\router_monitor_ed25519`. Приватный ключ нельзя добавлять в репозиторий.

## GitHub Actions

Workflow использует только .NET SDK и собирает self-contained Windows EXE. Теги `v*` автоматически публикуются как GitHub Release.

## Безопасность

SSH-доступ выполняется по отдельному Ed25519-ключу. SSH-терминал доступен только в desktop-приложении; web-панель его не предоставляет.
