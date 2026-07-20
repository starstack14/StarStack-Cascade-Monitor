using System.Text;
using System.IO;
using System.Windows;
using System.Windows.Input;
using Renci.SshNet;

namespace StarStack.CascadeMonitor;

public partial class SshTerminalWindow : Window
{
    private readonly string _host, _username, _keyPath;
    private readonly int _port;
    private SshClient? _client;
    private ShellStream? _shell;
    private readonly CancellationTokenSource _stop = new();
    public SshTerminalWindow(string host, string username, string keyPath, int port = 22)
    {
        InitializeComponent(); _host = host; _username = username; _keyPath = keyPath; _port = port;
        Closed += (_, _) => Disconnect(); Loaded += (_, _) => ConnectAsync();
    }
    private async void ConnectAsync()
    {
        try
        {
            if (!File.Exists(_keyPath)) throw new FileNotFoundException("SSH private key не найден", _keyPath);
            await Task.Run(() => { var key = new PrivateKeyFile(_keyPath); var info = new ConnectionInfo(_host, _port, _username, new PrivateKeyAuthenticationMethod(_username, key)); _client = new SshClient(info); _client.Connect(); _shell = _client.CreateShellStream("xterm", 120, 36, 1280, 720, 4096); });
            StatusText.Text = "ONLINE"; StatusText.Foreground = System.Windows.Media.Brushes.LightGreen; Append("SSH-сессия подключена.\r\n"); _ = Task.Run(ReadLoop); CommandBox.Focus();
        }
        catch (Exception ex) { StatusText.Text = "ERROR"; StatusText.Foreground = System.Windows.Media.Brushes.IndianRed; Append($"Не удалось подключиться: {ex.Message}\r\n"); }
    }
    private void ReadLoop()
    {
        var buffer = new byte[4096];
        while (!_stop.IsCancellationRequested && _shell is { } shell && shell.CanRead)
        { try { if (!shell.DataAvailable) { Thread.Sleep(50); continue; } var count = shell.Read(buffer, 0, buffer.Length); if (count > 0) Append(Encoding.UTF8.GetString(buffer, 0, count)); } catch { break; } }
    }
    private void Append(string text) => Dispatcher.Invoke(() => { OutputBox.AppendText(text); OutputBox.ScrollToEnd(); });
    private void Send_Click(object sender, RoutedEventArgs e) => SendCommand();
    private void CommandBox_KeyDown(object sender, System.Windows.Input.KeyEventArgs e) { if (e.Key == Key.Enter) { SendCommand(); e.Handled = true; } }
    private void SendCommand() { if (_shell is null || _client?.IsConnected != true) return; var command = CommandBox.Text; if (string.IsNullOrWhiteSpace(command)) return; _shell.WriteLine(command); CommandBox.Clear(); }
    private void Close_Click(object sender, RoutedEventArgs e) => Close();
    private void Disconnect() { _stop.Cancel(); try { _shell?.Dispose(); _client?.Disconnect(); _client?.Dispose(); } catch { } }
}
