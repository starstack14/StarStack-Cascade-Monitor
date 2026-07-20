using System.Diagnostics;
using System.IO;
using System.Windows;

namespace StarStack.CascadeMonitor;

public partial class MainWindow : Window
{
    public MainWindow() => InitializeComponent();
    private void OpenEmbeddedSsh_Click(object sender, RoutedEventArgs e) => new SshTerminalWindow("192.168.11.1", "root", FindSshKey()) { Owner = this }.Show();
    private void OpenWindowsTerminal_Click(object sender, RoutedEventArgs e)
    {
        try { var key = FindSshKey(); Process.Start(new ProcessStartInfo("wt.exe", $"new-tab ssh -i \"{key}\" -p 22 root@192.168.11.1") { UseShellExecute = true }); }
        catch (Exception ex) { MessageBox.Show(ex.Message, "Windows Terminal недоступен", MessageBoxButton.OK, MessageBoxImage.Warning); }
    }
    private void Refresh_Click(object sender, RoutedEventArgs e) => MessageBox.Show("Обновление данных будет подключено следующим этапом.", "StarStack", MessageBoxButton.OK, MessageBoxImage.Information);
    private static string FindSshKey()
    {
        var candidates = new[] { Path.Combine(AppContext.BaseDirectory, "keys", "router_monitor_ed25519"), Path.Combine(Environment.CurrentDirectory, "keys", "router_monitor_ed25519"), @"D:\StarStack-Cascade-Monitor\keys\router_monitor_ed25519" };
        return candidates.FirstOrDefault(File.Exists) ?? candidates[0];
    }
}
