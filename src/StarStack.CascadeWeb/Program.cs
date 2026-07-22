using System.Net.Http.Headers;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddHttpClient("remna", c => c.Timeout = TimeSpan.FromSeconds(8));
var app = builder.Build();
var user = Environment.GetEnvironmentVariable("DASHBOARD_USER") ?? "admin";
var password = Environment.GetEnvironmentVariable("DASHBOARD_PASSWORD") ?? throw new InvalidOperationException("DASHBOARD_PASSWORD is required");
var panel = (Environment.GetEnvironmentVariable("REMNAWAVE_URL") ?? "").TrimEnd('/');
var token = Environment.GetEnvironmentVariable("REMNAWAVE_TOKEN") ?? "";
var query = Environment.GetEnvironmentVariable("REMNAWAVE_QUERY") ?? "";

app.Use(async (ctx, next) => {
    if (ctx.Request.Path.StartsWithSegments("/health")) { await next(); return; }
    var header = ctx.Request.Headers.Authorization.ToString();
    if (!header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase)) { ctx.Response.Headers.WWWAuthenticate = "Basic realm=StarStack"; ctx.Response.StatusCode = 401; return; }
    try { var raw = Convert.FromBase64String(header[6..]); var pair = System.Text.Encoding.UTF8.GetString(raw).Split(':', 2); if (pair.Length != 2 || pair[0] != user || pair[1] != password) { ctx.Response.StatusCode = 401; return; } } catch { ctx.Response.StatusCode = 401; return; }
    await next();
});
app.MapGet("/health", () => Results.Ok(new { ok = true, service = "starstack-cascade-web" }));
app.MapGet("/api/dashboard", async (IHttpClientFactory factory, CancellationToken ct) => {
    if (string.IsNullOrWhiteSpace(panel) || string.IsNullOrWhiteSpace(token)) return Results.Problem("Remnawave is not configured");
    var endpoint = panel + "/api/nodes" + (string.IsNullOrWhiteSpace(query) ? "" : (query.StartsWith('?') ? query : "?" + query));
    using var req = new HttpRequestMessage(HttpMethod.Get, endpoint); req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
    using var res = await factory.CreateClient("remna").SendAsync(req, ct); var body = await res.Content.ReadAsStringAsync(ct);
    if (!res.IsSuccessStatusCode) return Results.Problem("Remnawave API unavailable", statusCode: (int)res.StatusCode);
    using var doc = JsonDocument.Parse(body); return Results.Json(new { updatedAt = DateTimeOffset.UtcNow, nodes = doc.RootElement.Clone() });
});
const string Html = """
<!doctype html><html lang='ru'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'><title>StarStack Cascade</title><style>
body{margin:0;background:#0b0a10;color:#f4edf2;font:14px Segoe UI,Arial}main{max-width:1100px;margin:28px auto;padding:0 20px}.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}.ok{color:#62e6a7}.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:14px}.card{background:#241721;border:1px solid #563448;border-radius:14px;padding:18px}.flow{display:flex;align-items:center;justify-content:space-around;background:#241721;border:1px solid #563448;border-radius:14px;padding:16px;margin-bottom:14px}.node{background:#321b2b;padding:12px 20px;border-radius:9px}.muted{color:#a98da0}.metric{margin-top:14px;color:#cdb7c5}table{width:100%;border-collapse:collapse}td,th{padding:9px;border-bottom:1px solid #563448;text-align:left}@media(max-width:700px){.grid{grid-template-columns:1fr}.flow{font-size:12px}}
</style></head><body><main><div class='top'><div><h1>StarStack</h1><span class='muted'>READ-ONLY CASCADE DASHBOARD</span></div><span id='status' class='ok'>CHECKING</span></div><div class='flow'><div class='node'>NX31</div><b>→</b><div class='node'>🇷🇺 Moscow</div><b>→</b><div class='node'>🇩🇪 Germany</div></div><div id='cards' class='grid'></div><div class='card' style='margin-top:14px'><h2>Подключённые ноды</h2><table><thead><tr><th>Нода</th><th>Статус</th><th>Load</th><th>RAM</th><th>Пользователи</th></tr></thead><tbody id='rows'></tbody></table></div></main><script>async function load(){try{let r=await fetch('/api/dashboard');if(!r.ok)throw 0;let j=await r.json(),a=j.nodes.response||j.nodes.nodes||j.nodes.data||[];document.querySelector('#status').textContent='CASCADE OK';document.querySelector('#rows').innerHTML=a.map(n=>{let s=n.system?.stats||{},i=n.system?.info||{},ram=i.memoryTotal?((s.memoryUsed||0)/i.memoryTotal*100):0,l=(s.loadAvg||[n.load||0])[0];return `<tr><td>${n.name||'Node'}</td><td class='ok'>${n.isConnected?'ONLINE':'OFFLINE'}</td><td>${Number(l).toFixed(2)}</td><td>${ram.toFixed(0)}%</td><td>${n.usersOnline||0}</td></tr>`}).join('')}catch(e){document.querySelector('#status').textContent='API ERROR'}}load();setInterval(load,10000)</script></body></html>
""";
app.MapGet("/", () => Results.Content(Html, "text/html; charset=utf-8"));
app.Run();
