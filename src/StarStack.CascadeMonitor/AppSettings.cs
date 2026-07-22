using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.IO;

namespace StarStack.CascadeMonitor;

public sealed class AppSettings
{
    public string RouterHost { get; set; } = "192.168.11.1";
    public string RouterUsername { get; set; } = "root";
    public int RouterPort { get; set; } = 22;
    public string PrivateKeyPath { get; set; } = "keys/router_monitor_ed25519";
    public string PanelUrl { get; set; } = "";
    public string AccessQuery { get; set; } = "";
    public string ApiTokenProtected { get; set; } = "";
    public string ActiveProfile { get; set; } = "home";
    public bool NotificationsEnabled { get; set; } = true;
    public bool AutoStart { get; set; } = true;
    public bool MinimizeToTray { get; set; } = true;
    public string GitHubRepository { get; set; } = "starstack14/StarStack-Cascade-Monitor";
    public static string Path => System.IO.Path.Combine(AppContext.BaseDirectory, "appsettings.json");
    public string ApiToken => string.IsNullOrWhiteSpace(ApiTokenProtected) ? "" : Dpapi.Unprotect(ApiTokenProtected);
    public void SetApiToken(string value) => ApiTokenProtected = Dpapi.Protect(value);
    public void Save() => File.WriteAllText(Path, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
    public static AppSettings Load()
    {
        try
        {
            var settings = File.Exists(Path) ? JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(Path)) ?? new() : new();
            if (string.IsNullOrWhiteSpace(settings.AccessQuery))
            {
                foreach (var candidate in LegacyConfigCandidates())
                {
                    if (!File.Exists(candidate)) continue;
                    using var doc = JsonDocument.Parse(File.ReadAllText(candidate));
                    if (doc.RootElement.TryGetProperty("access_query_dpapi", out var value))
                    {
                        var migrated = Dpapi.Unprotect(value.GetString() ?? "");
                        if (!string.IsNullOrWhiteSpace(migrated)) { settings.AccessQuery = migrated; settings.Save(); break; }
                    }
                }
            }
            return settings;
        }
        catch { return new(); }
    }
    private static IEnumerable<string> LegacyConfigCandidates()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (var i = 0; i < 7 && dir is not null; i++, dir = dir.Parent)
            yield return System.IO.Path.Combine(dir.FullName, "config.local.json");
        yield return @"D:\StarStack-Cascade-Monitor\config.local.json";
    }
}

public static class Dpapi
{
    public static string Protect(string value) => string.IsNullOrEmpty(value) ? "" : Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(value), null, DataProtectionScope.CurrentUser));
    public static string Unprotect(string value) { try { return string.IsNullOrEmpty(value) ? "" : Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(value), null, DataProtectionScope.CurrentUser)); } catch { return ""; } }
}
