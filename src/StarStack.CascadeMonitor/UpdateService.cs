using System.Net.Http.Headers;
using System.Net.Http;
using System.Text.Json;

namespace StarStack.CascadeMonitor;

public sealed record UpdateInfo(bool Available, string Version, string Url);

public sealed class UpdateService
{
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(8) };
    public async Task<UpdateInfo> CheckAsync(string repository, string currentVersion, string? token = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(repository)) return new(false, currentVersion, "");
        using var request = new HttpRequestMessage(HttpMethod.Get, $"https://api.github.com/repos/{repository}/releases/latest"); request.Headers.UserAgent.Add(new ProductInfoHeaderValue("StarStack-Cascade-Monitor", currentVersion)); if (!string.IsNullOrWhiteSpace(token)) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await _http.SendAsync(request, cancellationToken); if (!response.IsSuccessStatusCode) return new(false, currentVersion, ""); using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken)); var tag = doc.RootElement.GetProperty("tag_name").GetString() ?? currentVersion; var url = doc.RootElement.GetProperty("html_url").GetString() ?? "";
        return new(Compare(tag, currentVersion) > 0, tag, url);
    }
    private static int Compare(string left, string right) { static Version Parse(string value) => Version.TryParse(value.TrimStart('v', 'V'), out var v) ? v : new Version(0, 0); return Parse(left).CompareTo(Parse(right)); }
}
