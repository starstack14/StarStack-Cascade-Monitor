using Microsoft.Data.Sqlite;

namespace StarStack.CascadeMonitor;

public sealed class HistoryStore
{
    private readonly string _connection;
    public HistoryStore() { _connection = $"Data Source={System.IO.Path.Combine(AppContext.BaseDirectory, "history.db")}"; using var db = Open(); using var cmd = db.CreateCommand(); cmd.CommandText = "CREATE TABLE IF NOT EXISTS samples(ts INTEGER PRIMARY KEY, router_online INTEGER, singbox_online INTEGER, load REAL, ram REAL, error TEXT)"; cmd.ExecuteNonQuery(); }
    private SqliteConnection Open() { var db = new SqliteConnection(_connection); db.Open(); return db; }
    public void Record(RouterStatus status) { using var db = Open(); using var cmd = db.CreateCommand(); cmd.CommandText = "INSERT INTO samples VALUES($ts,$online,$singbox,$load,$ram,$error)"; cmd.Parameters.AddWithValue("$ts", DateTimeOffset.UtcNow.ToUnixTimeSeconds()); cmd.Parameters.AddWithValue("$online", status.Online ? 1 : 0); cmd.Parameters.AddWithValue("$singbox", status.SingBoxRunning ? 1 : 0); cmd.Parameters.AddWithValue("$load", status.Load); cmd.Parameters.AddWithValue("$ram", status.RamPercent); cmd.Parameters.AddWithValue("$error", status.Error); cmd.ExecuteNonQuery(); }
    public (int samples, int failures, double uptime) WeeklySummary() { using var db = Open(); using var cmd = db.CreateCommand(); cmd.CommandText = "SELECT COUNT(*), COALESCE(SUM(CASE WHEN router_online=0 OR singbox_online=0 THEN 1 ELSE 0 END),0) FROM samples WHERE ts >= $since"; cmd.Parameters.AddWithValue("$since", DateTimeOffset.UtcNow.AddDays(-7).ToUnixTimeSeconds()); using var r = cmd.ExecuteReader(); r.Read(); var samples = r.GetInt32(0); var failures = r.GetInt32(1); return (samples, failures, samples == 0 ? 0 : (samples - failures) * 100.0 / samples); }
    public List<(double Load, double Ram, bool Online)> Recent(int limit = 120) { using var db = Open(); using var cmd = db.CreateCommand(); cmd.CommandText = "SELECT load, ram, router_online FROM samples ORDER BY ts DESC LIMIT $limit"; cmd.Parameters.AddWithValue("$limit", limit); using var r = cmd.ExecuteReader(); var rows = new List<(double, double, bool)>(); while (r.Read()) rows.Add((r.GetDouble(0), r.GetDouble(1), r.GetInt32(2) == 1)); rows.Reverse(); return rows; }
}
