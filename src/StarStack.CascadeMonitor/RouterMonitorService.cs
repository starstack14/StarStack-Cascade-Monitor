using System.Text.Json;
using Renci.SshNet;

namespace StarStack.CascadeMonitor;

public sealed record RouterStatus(bool Online, bool SingBoxRunning, string Hostname, double Load, double RamPercent, long Uptime, string Error = "");

public sealed class RouterMonitorService
{
    private readonly string _host, _username, _keyPath;
    private readonly int _port;
    public RouterMonitorService(string host, string username, string keyPath, int port = 22) { _host = host; _username = username; _keyPath = keyPath; _port = port; }
    public RouterStatus Read()
    {
        try
        {
            using var client = new SshClient(new ConnectionInfo(_host, _port, _username, new PrivateKeyAuthenticationMethod(_username, new PrivateKeyFile(_keyPath))));
            client.Connect();
            using var board = JsonDocument.Parse(client.RunCommand("ubus call system board").Result);
            using var info = JsonDocument.Parse(client.RunCommand("ubus call system info").Result);
            using var service = JsonDocument.Parse(client.RunCommand("ubus call service list").Result);
            var load = info.RootElement.GetProperty("load")[0].GetInt64() / 65535.0;
            var memory = info.RootElement.GetProperty("memory");
            var total = memory.GetProperty("total").GetInt64(); var available = memory.GetProperty("available").GetInt64();
            return new RouterStatus(true, HasRunningService(service.RootElement, "sing-box"), board.RootElement.GetProperty("hostname").GetString() ?? "NX31", load, total > 0 ? (total - available) * 100.0 / total : 0, info.RootElement.GetProperty("uptime").GetInt64());
        }
        catch (Exception ex) { return new RouterStatus(false, false, "NX31", 0, 0, 0, ex.Message); }
    }
    private static bool HasRunningService(JsonElement element, string name)
    {
        if (element.ValueKind == JsonValueKind.Object)
        { foreach (var p in element.EnumerateObject()) if ((p.Name.Contains(name, StringComparison.OrdinalIgnoreCase) && p.Value.ValueKind == JsonValueKind.Object && p.Value.TryGetProperty("instances", out var instances) && HasRunningInstance(instances)) || HasRunningService(p.Value, name)) return true; }
        else if (element.ValueKind == JsonValueKind.Array) foreach (var item in element.EnumerateArray()) if (HasRunningService(item, name)) return true;
        return false;
    }
    private static bool HasRunningInstance(JsonElement element) => element.ValueKind == JsonValueKind.Object && element.EnumerateObject().Any(p => p.Value.ValueKind == JsonValueKind.Object && p.Value.TryGetProperty("running", out var running) && running.ValueKind == JsonValueKind.True);
}
