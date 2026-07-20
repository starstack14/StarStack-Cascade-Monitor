using System.Diagnostics;
using System.Windows;

namespace StarStack.CascadeMonitor;

public partial class MainWindow : Window
{
    public MainWindow() => InitializeComponent();

    private void OpenEmbeddedSsh_Click(object sender, RoutedEventArgs e) =>
        MessageBox.Show("На следующем этапе сюда подключится встроенный SSH-терминал NX31 через SSH.NET.", "SSH-терминал", MessageBoxButton.OK, MessageBoxImage.Information);

    private void OpenWindowsTerminal_Click(object sender, RoutedEventArgs e)
    {
        try { Process.Start(new ProcessStartInfo("wt.exe") { UseShellExecute = true }); }
        catch (Exception ex) { MessageBox.Show(ex.Message, "Windows Terminal недоступен", MessageBoxButton.OK, MessageBoxImage.Warning); }
    }

    private void Refresh_Click(object sender, RoutedEventArgs e) =>
        MessageBox.Show("Каркас .NET готов. Подключение данных будет добавлено следующим этапом.", "StarStack", MessageBoxButton.OK, MessageBoxImage.Information);
}
