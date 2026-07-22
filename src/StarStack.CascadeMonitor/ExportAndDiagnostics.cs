using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.IO;

namespace StarStack.CascadeMonitor;

public sealed record TlsInfo(bool Available, int DaysRemaining, string Error = "");
public static class Diagnostics
{
    public static string Explain(RouterStatus router, IReadOnlyList<RemnawaveNode> nodes, string apiError)
    {
        if (!router.Online) return "NX31: SSH недоступен — проверьте адрес, ключ и сеть.";
        if (!router.SingBoxRunning) return "NX31: sing-box не запущен.";
        if (!string.IsNullOrWhiteSpace(apiError)) return "Remnawave: API недоступен или отклоняет запрос.";
        if (nodes.Any(n => !n.Online)) return "Каскад: одна из нод offline.";
        return "Сбоев не обнаружено.";
    }
    public static async Task<TlsInfo> CheckTlsAsync(string panelUrl)
    {
        try
        {
            var uri = new Uri(panelUrl); using var tcp = new TcpClient(); await tcp.ConnectAsync(uri.Host, 443);
            using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true); await ssl.AuthenticateAsClientAsync(uri.Host);
            var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(ssl.RemoteCertificate!);
            return new(true, (int)Math.Floor((cert.NotAfter - DateTime.UtcNow).TotalDays));
        }
        catch (Exception ex) { return new(false, 0, ex.Message); }
    }
}

public static class ReportExporter
{
    public static string ExportHtml(HistoryStore history)
    {
        var s = history.WeeklySummary(); var rows = history.Recent(100);
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "StarStack-Cascade-Report.html");
        var html = $"<html><meta charset='utf-8'><style>body{{font:14px Segoe UI;background:#160c13;color:#fff}}td,th{{padding:6px;border-bottom:1px solid #633}}</style><h1>StarStack Cascade Monitor</h1><p>Uptime: {s.uptime:0.0}% · Samples: {s.samples} · Failures: {s.failures}</p><table><tr><th>Load</th><th>RAM</th><th>Online</th></tr>{string.Join("", rows.Select(r => $"<tr><td>{r.Load:0.00}</td><td>{r.Ram:0.0}%</td><td>{r.Online}</td></tr>"))}</table></html>";
        File.WriteAllText(path, html, Encoding.UTF8); return path;
    }
    public static string ExportPdf(HistoryStore history)
    {
        var s = history.WeeklySummary(); var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "StarStack-Cascade-Report.pdf");
        var text = $"StarStack Cascade Monitor\\nUptime: {s.uptime:0.0}%\\nSamples: {s.samples}\\nFailures: {s.failures}";
        var stream = $"BT /F1 16 Tf 72 740 Td ({text.Replace("\\n", ") Tj 0 -24 Td (")}) Tj ET";
        var pdf = "%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<</Font<</F1 4 0 R>>>>/Contents 5 0 R>>endobj\n4 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\n5 0 obj<</Length " + Encoding.ASCII.GetByteCount(stream) + ">>stream\n" + stream + "\nendstream endobj\ntrailer<</Root 1 0 R>>\n%%EOF";
        File.WriteAllText(path, pdf, Encoding.ASCII); return path;
    }
}

public static class BackupService
{
    public static string Create(AppSettings settings)
    {
        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "StarStack-Backups"); Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, $"backup-{DateTime.Now:yyyyMMdd-HHmmss}.json"); File.Copy(AppSettings.Path, path, true); return path;
    }
    public static void Restore(string path) { File.Copy(path, AppSettings.Path, true); }
}

public static class SpeedTestService
{
    public static async Task<long> MeasureLatencyAsync(string host, int port = 443)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew(); using var tcp = new TcpClient(); await tcp.ConnectAsync(host, port); return sw.ElapsedMilliseconds;
    }
}
