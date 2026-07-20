using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;

namespace StarStack.CascadeMonitor;

public partial class MainWindow : Window
{
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(10) };
    public MainWindow()
    {
        InitializeComponent(); _timer.Tick += (_, _) => RefreshRouterStatus(); _timer.Start(); Loaded += (_, _) => RefreshRouterStatus();
    }
    private void RefreshRouterStatus()
    {
        var service = new RouterMonitorService("192.168.11.1", "root", FindSshKey());
        Task.Run(service.Read).ContinueWith(t => Dispatcher.Invoke(() => RenderStatus(t.Result)));
    }
    private void RenderStatus(RouterStatus status)
    {
        RouterStatusText.Text = status.Online ? "NX31 ONLINE" : "NX31 OFFLINE"; RouterStatusText.Foreground = status.Online ? Brushes.LightGreen : Brushes.IndianRed;
        CascadeStatusText.Text = status.Online && status.SingBoxRunning ? "CASCADE READY" : "CASCADE CHECK"; CascadeStatusText.Foreground = status.Online && status.SingBoxRunning ? Brushes.LightGreen : Brushes.Orange;
        MoscowStatusText.Text = status.Online && status.SingBoxRunning ? "ONLINE" : "CHECK"; MoscowStatusText.Foreground = status.Online ? Brushes.LightGreen : Brushes.IndianRed;
        MoscowMetricsText.Text = $"Router uptime {TimeSpan.FromSeconds(status.Uptime):dd\\:hh\\:mm} / Load {status.Load:0.00} / RAM {status.RamPercent:0}%"; MoscowLoadBar.Value = Math.Min(status.Load * 100, 100);
        GermanyStatusText.Text = status.Online ? "API CHECK" : "WAITING"; GermanyMetricsText.Text = status.Error.Length == 0 ? "Moscow link / Germany status pending" : status.Error; GermanyLoadBar.Value = 0;
    }
    private void OpenEmbeddedSsh_Click(object sender, RoutedEventArgs e) => new SshTerminalWindow("192.168.11.1", "root", FindSshKey()) { Owner = this }.Show();
    private void OpenWindowsTerminal_Click(object sender, RoutedEventArgs e) { try { var key = FindSshKey(); Process.Start(new ProcessStartInfo("wt.exe", $"new-tab ssh -i \"{key}\" -p 22 root@192.168.11.1") { UseShellExecute = true }); } catch (Exception ex) { MessageBox.Show(ex.Message, "Windows Terminal unavailable", MessageBoxButton.OK, MessageBoxImage.Warning); } }
    private void Refresh_Click(object sender, RoutedEventArgs e) => RefreshRouterStatus();
    private static string FindSshKey() { var candidates = new[] { Path.Combine(AppContext.BaseDirectory, "keys", "router_monitor_ed25519"), Path.Combine(Environment.CurrentDirectory, "keys", "router_monitor_ed25519"), @"D:\StarStack-Cascade-Monitor\keys\router_monitor_ed25519" }; return candidates.FirstOrDefault(File.Exists) ?? candidates[0]; }
}
