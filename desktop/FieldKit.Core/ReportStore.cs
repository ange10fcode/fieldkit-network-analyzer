using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace FieldKit.Core;

/// <summary>Per-user local observations. Atomic replacement preserves the previous document if a write fails.</summary>
public sealed partial class ReportStore
{
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> Locks = new(StringComparer.OrdinalIgnoreCase);
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true, PropertyNameCaseInsensitive = true };
    private readonly string directory;
    private readonly SemaphoreSlim gate;
    private const int MaxDocumentBytes = 32 * 1024 * 1024;
    private const int MaxHistory = 500;
    public string DirectoryPath => directory;

    public ReportStore(string? directory = null)
    {
        this.directory = Path.GetFullPath(directory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "FieldKit"));
        gate = Locks.GetOrAdd(this.directory, _ => new SemaphoreSlim(1, 1));
    }

    public async Task SaveAsync(Report report, CancellationToken cancellationToken = default)
    {
        ValidateReport(report);
        var key = Key(report.Tool);
        var envelope = new SavedReport(1, DateTimeOffset.UtcNow, report);
        var document = JsonSerializer.SerializeToUtf8Bytes(envelope, JsonOptions);
        if (document.Length > MaxDocumentBytes) throw new ArgumentException("The report is too large to retain locally.");
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            Directory.CreateDirectory(directory);
            await AtomicWriteAsync(Path.Combine(directory, $"latest-{key}.json"), document, cancellationToken).ConfigureAwait(false);
            var history = Path.Combine(directory, "history"); Directory.CreateDirectory(history);
            var filename = $"{DateTimeOffset.UtcNow.UtcTicks:D19}-{Guid.NewGuid():N}.json";
            await AtomicWriteAsync(Path.Combine(history, filename), document, cancellationToken).ConfigureAwait(false);
            foreach (var old in Directory.EnumerateFiles(history, "*.json").OrderByDescending(Path.GetFileName, StringComparer.Ordinal).Skip(MaxHistory))
                File.Delete(old);
        }
        finally { gate.Release(); }
    }

    public async Task<Report?> LoadLatestAsync(string tool, CancellationToken cancellationToken = default)
    {
        var path = Path.Combine(directory, $"latest-{Key(tool)}.json");
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { return await ReadReportAsync(path, cancellationToken).ConfigureAwait(false); }
        finally { gate.Release(); }
    }

    public async Task<IReadOnlyList<Report>> LoadHistoryAsync(CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var result = new List<Report>(); var history = Path.Combine(directory, "history");
            if (!Directory.Exists(history)) return result;
            foreach (var path in Directory.EnumerateFiles(history, "*.json").OrderByDescending(Path.GetFileName, StringComparer.Ordinal).Take(MaxHistory))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var report = await ReadReportAsync(path, cancellationToken).ConfigureAwait(false);
                if (report is not null) result.Add(report);
            }
            return result;
        }
        finally { gate.Release(); }
    }

    public async Task<IReadOnlyList<Favorite>> FavoritesAsync(CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var bytes = await ReadBytesAsync(Path.Combine(directory, "favorites.json"), cancellationToken).ConfigureAwait(false);
            if (bytes is null) return [];
            try
            {
                var favorites = JsonSerializer.Deserialize<List<Favorite>>(bytes, JsonOptions) ?? [];
                return favorites.Where(f => f is not null && f.Name is not null && f.Tool is not null && f.Target is not null).Take(200).ToList();
            }
            catch (JsonException) { return []; }
        }
        finally { gate.Release(); }
    }

    public async Task SaveFavoritesAsync(IEnumerable<Favorite> favorites, CancellationToken cancellationToken = default)
    {
        var items = favorites.Take(201).ToList();
        if (items.Count > 200 || items.Any(f => f.Name.Length > 256 || f.Tool.Length > 64 || f.Target.Length > 1024 || f.Extra?.Length > 32768))
            throw new ArgumentException("Keep at most 200 favorites with concise names and targets.");
        var bytes = JsonSerializer.SerializeToUtf8Bytes(items, JsonOptions);
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            Directory.CreateDirectory(directory);
            await AtomicWriteAsync(Path.Combine(directory, "favorites.json"), bytes, cancellationToken).ConfigureAwait(false);
        }
        finally { gate.Release(); }
    }

    public async Task ClearLatestAsync(string tool, CancellationToken cancellationToken = default)
    {
        var path = Path.Combine(directory, $"latest-{Key(tool)}.json");
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { File.Delete(path); }
        finally { gate.Release(); }
    }

    public async Task ClearHistoryAsync(CancellationToken cancellationToken = default)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var history = Path.Combine(directory, "history");
            if (Directory.Exists(history)) foreach (var path in Directory.EnumerateFiles(history, "*.json")) File.Delete(path);
        }
        finally { gate.Release(); }
    }

    public static string ExportJson(Report report) { ValidateReport(report); return JsonSerializer.Serialize(report, JsonOptions); }

    public static string ExportCsv(Report report)
    {
        ValidateReport(report);
        var text = new StringBuilder();
        void Row(IEnumerable<string> values) => text.AppendLine(string.Join(',', values.Select(CsvCell)));
        Row(["FieldKit report", report.Title]); Row(["Captured", report.CreatedAt.ToString("O")]);
        foreach (var summary in report.Summary) Row(["Summary", summary]);
        text.AppendLine(); Row(report.Columns);
        foreach (var row in report.Rows) Row(row);
        return text.ToString();
    }

    private static string CsvCell(string value)
    {
        // Spreadsheet applications can interpret network-controlled text as formulas.
        // Prefix dangerous leading characters while keeping the original data exact in JSON.
        if (value.Length > 0 && (value[0] is '\t' or '\r' || value.TrimStart().FirstOrDefault() is '=' or '+' or '-' or '@')) value = "'" + value;
        return "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }

    private static async Task<Report?> ReadReportAsync(string path, CancellationToken token)
    {
        var bytes = await ReadBytesAsync(path, token).ConfigureAwait(false);
        if (bytes is null) return null;
        try
        {
            var envelope = JsonSerializer.Deserialize<SavedReport>(bytes, JsonOptions);
            if (envelope?.Format != 1 || envelope.Report is null) return null;
            ValidateReport(envelope.Report); return envelope.Report;
        }
        catch (Exception error) when (error is JsonException or ArgumentException or NullReferenceException) { return null; }
    }

    private static async Task<byte[]?> ReadBytesAsync(string path, CancellationToken token)
    {
        if (!File.Exists(path)) return null;
        var info = new FileInfo(path);
        if (info.Length > MaxDocumentBytes) return null;
        return await File.ReadAllBytesAsync(path, token).ConfigureAwait(false);
    }

    private static async Task AtomicWriteAsync(string path, byte[] bytes, CancellationToken token)
    {
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 8192,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(bytes, token).ConfigureAwait(false);
                await stream.FlushAsync(token).ConfigureAwait(false);
                stream.Flush(true);
            }
            token.ThrowIfCancellationRequested(); File.Move(temporary, path, true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    private static string Key(string key) => SafeKey().IsMatch(key) ? key : throw new ArgumentException("The saved tool identifier is not valid.");
    [GeneratedRegex("^[a-z][a-z0-9_-]{0,39}$", RegexOptions.CultureInvariant)] private static partial Regex SafeKey();
    private static void ValidateReport(Report report)
    {
        if (report is null || report.Title is null || report.Columns is null || report.Rows is null || report.Summary is null ||
            report.Columns.Count > 128 || report.Rows.Count > 20000 || report.Rows.Any(r => r is null || r.Count != report.Columns.Count || r.Any(c => c is null || c.Length > 65536)) ||
            report.Columns.Any(c => c is null) || report.Summary.Any(c => c is null)) throw new ArgumentException("The report is incomplete or exceeds the supported limits.");
        _ = Key(report.Tool);
    }

    private sealed record SavedReport(int Format, DateTimeOffset SavedAt, Report Report);
}
