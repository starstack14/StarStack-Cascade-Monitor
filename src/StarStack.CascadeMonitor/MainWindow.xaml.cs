using System.Diagnostics;
using System.IO;
using System.Windows;
using MediaBrushes = System.Windows.Media.Brushes;
using WpfApplication = System.Windows.Application;
using WpfMessageBox = System.Windows.MessageBox;
using System.Windows.Threading;
using Forms = System.Windows.Forms;

namespace StarStack.CascadeMonitor;

public partial class MainWindow : Window
{
    private const string AppVersion = "3.0.0";
    private readonly AppSettings _settings = AppSettings.Load();
    private readonly HistoryStore _history = new();
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(10) };
    private Forms.NotifyIcon? _tray;
    private bool _exitRequested;
    private bool _refreshRunning;
    private bool _previousOnline;

    public MainWindow()
    {
        InitializeComponent();
        SetupTray();
        _timer.Tick += (_, _) => RefreshStatus();
        Loaded += (_, _) => { ApplyAutoStart(); RefreshStatus(); };
        Closing += MainWindow_Closing;
    }

    private void RefreshStatus()
    {
        if (_refreshRunning) return; _refreshRunning = true;
        var router = new RouterMonitorService(_settings.RouterHost, _settings.RouterUsername, ResolveKey(), _settings.RouterPort);
        Task.Run(async () => { var status = router.Read(); IReadOnlyList<RemnawaveNode> nodes = Array.Empty<RemnawaveNode>(); var remnaError = ""; try { nodes = await new RemnawaveClient(_settings.PanelUrl, _settings.ApiToken, _settings.AccessQuery).GetNodesAsync(); } catch (Exception ex) { remnaError = ex.GetBaseException().Message; } return (status, nodes, remnaError); }).ContinueWith(t => Dispatcher.Invoke(() => { _refreshRunning = false; RenderStatus(t.Result.status, t.Result.nodes, t.Result.remnaError); }));
    }

    private void RenderStatus(RouterStatus router, IReadOnlyList<RemnawaveNode> nodes, string remnaError = "")
    {
        try { File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "dotnet-debug.log"), $"{DateTime.Now:O}\nRouterOnline={router.Online}\nSingBox={router.SingBoxRunning}\nError={router.Error}\nRemna={remnaError}\nKey={ResolveKey()}\n"); } catch { }
        _history.Record(router);
        RouterStatusText.Text = router.Online ? $"{router.Hostname} ONLINE" : "NX31 OFFLINE"; RouterStatusText.Foreground = router.Online ? MediaBrushes.LightGreen : MediaBrushes.IndianRed;
        CascadeStatusText.Text = router.Online && router.SingBoxRunning ? "CASCADE READY" : "CASCADE CHECK"; CascadeStatusText.Foreground = router.Online && router.SingBoxRunning ? MediaBrushes.LightGreen : MediaBrushes.Orange;
        MoscowStatusText.Text = router.Online && router.SingBoxRunning ? "ONLINE" : "CHECK"; MoscowStatusText.Foreground = router.Online ? MediaBrushes.LightGreen : MediaBrushes.IndianRed;
        MoscowMetricsText.Text = router.Online ? $"NX31 uptime {TimeSpan.FromSeconds(router.Uptime):dd\\:hh\\:mm} / Load {router.Load:0.00} / RAM {router.RamPercent:0}%" : $"SSH: {router.Error}"; MoscowLoadBar.Value = Math.Min(router.Load * 100, 100);
        var moscow = nodes.FirstOrDefault(n => n.Name.Contains("Moscow", StringComparison.OrdinalIgnoreCase) || n.Name.StartsWith("RU", StringComparison.OrdinalIgnoreCase));
        var germany = nodes.FirstOrDefault(n => n.Name.Contains("Germany", StringComparison.OrdinalIgnoreCase) || n.Name.StartsWith("DE", StringComparison.OrdinalIgnoreCase));
        RenderNode(MoscowStatusText, MoscowMetricsText, MoscowLoadBar, moscow, "Moscow"); RenderNode(GermanyStatusText, GermanyMetricsText, GermanyLoadBar, germany, "Germany");
        if (!string.IsNullOrWhiteSpace(remnaError)) { GermanyStatusText.Text = "API ERROR"; GermanyStatusText.Foreground = MediaBrushes.IndianRed; GermanyMetricsText.Text = remnaError.Length > 140 ? remnaError[..140] : remnaError; }
        if (_previousOnline && !router.Online && _settings.NotificationsEnabled) _tray?.ShowBalloonTip(5000, "StarStack Cascade Monitor", "NX31 недоступен по SSH", Forms.ToolTipIcon.Error);
        _previousOnline = router.Online;
    }
    private static void RenderNode(System.Windows.Controls.TextBlock status, System.Windows.Controls.TextBlock metrics, System.Windows.Controls.ProgressBar bar, RemnawaveNode? node, string name)
    { if (node is null) { status.Text = "NO DATA"; status.Foreground = MediaBrushes.Gray; metrics.Text = $"{name}: нет данных Remnawave"; bar.Value = 0; return; } status.Text = node.Online ? "ONLINE" : "OFFLINE"; status.Foreground = node.Online ? MediaBrushes.LightGreen : MediaBrushes.IndianRed; metrics.Text = $"Load {node.Load:0.00} / RAM {node.RamPercent:0}% / Users {node.Users}"; bar.Value = Math.Min(node.Load * 100, 100); }

    private void SetupTray()
    {
        _tray = new Forms.NotifyIcon { Icon = System.Drawing.SystemIcons.Application, Visible = true, Text = "StarStack Cascade Monitor" };
        var menu = new Forms.ContextMenuStrip(); menu.Items.Add("Открыть", null, (_, _) => Dispatcher.Invoke(ShowWindow)); menu.Items.Add("Настройки", null, (_, _) => Dispatcher.Invoke(OpenSettings)); menu.Items.Add("Недельный отчёт", null, (_, _) => Dispatcher.Invoke(ShowReport)); menu.Items.Add(new Forms.ToolStripSeparator()); menu.Items.Add("Выход", null, (_, _) => Dispatcher.Invoke(ExitApplication)); _tray.ContextMenuStrip = menu; _tray.DoubleClick += (_, _) => Dispatcher.Invoke(ShowWindow);
    }
    private void ShowWindow() { Show(); WindowState = WindowState.Normal; Activate(); }
    private void MainWindow_Closing(object? sender, System.ComponentModel.CancelEventArgs e) { if (!_exitRequested && _settings.MinimizeToTray) { e.Cancel = true; Hide(); } else { _tray?.Dispose(); } }
    private void ExitApplication() { _exitRequested = true; _tray?.Dispose(); WpfApplication.Current.Shutdown(); }
    private void Settings_Click(object sender, RoutedEventArgs e) => OpenSettings();
    private void OpenSettings() { var dialog = new SettingsWindow(_settings) { Owner = this }; if (dialog.ShowDialog() == true) RefreshStatus(); }
    private void Report_Click(object sender, RoutedEventArgs e) => ShowReport();
    private async void Updates_Click(object sender, RoutedEventArgs e)
    {
        try { var update = await new UpdateService().CheckAsync(_settings.GitHubRepository, AppVersion); WpfMessageBox.Show(update.Available ? $"Доступна версия {update.Version}\n{update.Url}" : "Установлена последняя версия.", "Обновления", MessageBoxButton.OK, MessageBoxImage.Information); }
        catch (Exception ex) { WpfMessageBox.Show(ex.Message, "Проверка обновлений", MessageBoxButton.OK, MessageBoxImage.Warning); }
    }
    private void ShowReport() { var s = _history.WeeklySummary(); WpfMessageBox.Show($"За последние 7 дней\n\nНаблюдений: {s.samples}\nСбоев: {s.failures}\nUptime: {s.uptime:0.0}%", "Недельный отчёт", MessageBoxButton.OK, MessageBoxImage.Information); new HistoryWindow(_history) { Owner = this }.Show(); }
    private void OpenEmbeddedSsh_Click(object sender, RoutedEventArgs e) => new SshTerminalWindow(_settings.RouterHost, _settings.RouterUsername, ResolveKey(), _settings.RouterPort) { Owner = this }.Show();
    private void OpenWindowsTerminal_Click(object sender, RoutedEventArgs e) { try { var key = ResolveKey(); Process.Start(new ProcessStartInfo("wt.exe", $"new-tab ssh -i \"{key}\" -p {_settings.RouterPort} {_settings.RouterUsername}@{_settings.RouterHost}") { UseShellExecute = true }); } catch (Exception ex) { WpfMessageBox.Show(ex.Message, "Windows Terminal unavailable", MessageBoxButton.OK, MessageBoxImage.Warning); } }
    private void Refresh_Click(object sender, RoutedEventArgs e) => RefreshStatus();
    private string ResolveKey()
    {
        if (Path.IsPathRooted(_settings.PrivateKeyPath) && File.Exists(_settings.PrivateKeyPath)) return _settings.PrivateKeyPath;
        var relative = _settings.PrivateKeyPath.Replace('/', Path.DirectorySeparatorChar);
        var candidates = new List<string> { Path.Combine(AppContext.BaseDirectory, relative), Path.Combine(Environment.CurrentDirectory, relative), @"D:\StarStack-Cascade-Monitor\keys\router_monitor_ed25519" };
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var i = 0; i < 6 && directory is not null; i++, directory = directory.Parent) candidates.Add(Path.Combine(directory.FullName, relative));
        return candidates.FirstOrDefault(File.Exists) ?? candidates[0];
    }
    private void ApplyAutoStart() { try { using var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run"); if (_settings.AutoStart) key?.SetValue("StarStackCascadeMonitorDotnet", Environment.ProcessPath ?? ""); else key?.DeleteValue("StarStackCascadeMonitorDotnet", false); } catch { } }
}
