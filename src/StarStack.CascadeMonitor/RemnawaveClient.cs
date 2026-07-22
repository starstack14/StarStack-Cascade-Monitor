using System.Net.Http.Headers;
using System.Net.Http;
using System.Net;
using System.Security.Authentication;
using System.Text.Json;

namespace StarStack.CascadeMonitor;

public sealed record RemnawaveNode(string Name, bool Online, double Load, double RamPercent, int Users, string Error = "");

public sealed class RemnawaveClient
{
    private readonly HttpClient _http;
    private readonly string _baseUrl, _token, _accessQuery;
    public RemnawaveClient(string baseUrl, string token, string accessQuery = "") { _baseUrl = baseUrl.TrimEnd('/'); _token = token; _accessQuery = NormalizeAccessQuery(accessQuery); _http = new HttpClient(new HttpClientHandler { SslProtocols = SslProtocols.Tls12 }) { Timeout = TimeSpan.FromSeconds(8), DefaultRequestVersion = HttpVersion.Version11, DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact }; }
    public async Task<IReadOnlyList<RemnawaveNode>> GetNodesAsync(CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(_baseUrl) || string.IsNullOrWhiteSpace(_token)) return Array.Empty<RemnawaveNode>();
        using var request = new HttpRequestMessage(HttpMethod.Get, Endpoint("/api/nodes")); request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
        using var response = await _http.SendAsync(request, cancellationToken); var body = await response.Content.ReadAsStringAsync(cancellationToken); if (!response.IsSuccessStatusCode) throw new InvalidOperationException($"Remnawave HTTP {(int)response.StatusCode}: {(body.Length > 160 ? body[..160] : body)}"); using var doc = JsonDocument.Parse(body);
        var result = new List<RemnawaveNode>(); var root = doc.RootElement; var array = FindArray(root, "nodes", "data", "response");
        if (array.ValueKind != JsonValueKind.Array) return result;
        foreach (var item in array.EnumerateArray())
        {
            var name = StringValue(item, "name", "nodeName", "remark") ?? "Node";
            var online = BoolValue(item, "isConnected", "online", "connected", "isOnline");
            var load = NumberValue(item, "load", "load1", "cpuLoad");
            if (load == 0) load = FirstArrayNumber(item, "system", "stats", "loadAvg");
            var ram = NumberValue(item, "ram", "ramPercent", "memoryPercent");
            if (ram == 0)
            {
                var used = NumberValue(item, "system", "stats", "memoryUsed");
                var total = NumberValue(item, "system", "info", "memoryTotal");
                if (total > 0) ram = used / total * 100;
            }
            var users = (int)NumberValue(item, "users", "usersCount", "onlineUsers", "usersOnline");
            result.Add(new(name, online, load, ram, users));
        }
        return result;
    }
    private string Endpoint(string path)
    {
        if (string.IsNullOrWhiteSpace(_accessQuery)) return _baseUrl + path;
        return _baseUrl + path + (_accessQuery.StartsWith("?") ? _accessQuery : "?" + _accessQuery);
    }
    private static string NormalizeAccessQuery(string value)
    {
        value = value.Trim();
        if (!value.StartsWith("{")) return value;
        try
        {
            using var doc = JsonDocument.Parse(value);
            return string.Join("&", doc.RootElement.EnumerateObject().Select(p => $"{Uri.EscapeDataString(p.Name)}={Uri.EscapeDataString(p.Value.ToString())}"));
        }
        catch { return value; }
    }
    private static JsonElement FindArray(JsonElement root, params string[] names) { if (root.ValueKind == JsonValueKind.Object) foreach (var p in root.EnumerateObject()) { if (names.Contains(p.Name, StringComparer.OrdinalIgnoreCase) && p.Value.ValueKind == JsonValueKind.Array) return p.Value; var nested = FindArray(p.Value, names); if (nested.ValueKind == JsonValueKind.Array) return nested; } else if (root.ValueKind == JsonValueKind.Array) return root; return default; }
    private static string? StringValue(JsonElement e, params string[] names) => names.Select(n => e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null).FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));
    private static bool BoolValue(JsonElement e, params string[] names) => names.Any(n => e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.True);
    private static double NumberValue(JsonElement e, params string[] names) => names.Select(n => e.TryGetProperty(n, out var v) && v.TryGetDouble(out var d) ? d : 0).FirstOrDefault(d => d != 0);
    private static double NumberValue(JsonElement e, string parent, string child, string name)
    {
        return e.TryGetProperty(parent, out var p) && p.TryGetProperty(child, out var c) && c.TryGetProperty(name, out var v) && v.TryGetDouble(out var d) ? d : 0;
    }
    private static double FirstArrayNumber(JsonElement e, string parent, string child, string name)
    {
        if (!e.TryGetProperty(parent, out var p) || !p.TryGetProperty(child, out var c) || !c.TryGetProperty(name, out var a) || a.ValueKind != JsonValueKind.Array) return 0;
        return a.EnumerateArray().Select(v => v.TryGetDouble(out var d) ? d : 0).FirstOrDefault();
    }
}
