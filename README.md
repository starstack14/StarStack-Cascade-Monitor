# StarStack Cascade Monitor · .NET WPF

Текущая единственная ветка проекта — `main`. Релиз `v3.0.2` добавляет диагностику каскада, экспорт HTML/PDF, тест задержки Moscow/Germany, TLS-проверку, backup/restore настроек, русский/английский выбор и компактный режим.

## Read-only web dashboard

`src/StarStack.CascadeWeb` — отдельный ASP.NET Core 8 dashboard. Он не предоставляет SSH и команды управления: только статус Remnawave и нод. Секреты задаются переменными окружения `DASHBOARD_PASSWORD`, `REMNAWAVE_TOKEN` и `REMNAWAVE_QUERY` и не хранятся в Git.

Проверка локально: `dotnet run --project src/StarStack.CascadeWeb`. Для Docker используется `src/StarStack.CascadeWeb/Dockerfile`. На сервере dashboard опубликован через `https://monitor.starstackcp.online` за Nginx и Basic Auth.

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
