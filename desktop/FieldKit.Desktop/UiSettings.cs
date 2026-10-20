using System.Text.Json;

namespace FieldKit.Desktop;

internal sealed class UiSettings
{
    public string Theme { get; set; } = "System";
    public string Tool { get; set; } = "networks";
    public Dictionary<string, string> Targets { get; set; } = new();
    public Dictionary<string, string> Extras { get; set; } = new();
    public double Width { get; set; } = 1180;
    public double Height { get; set; } = 800;
    internal static string? DataRootOverride { get; set; }
    public static string DataDirectory => DataRootOverride ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FieldKit");
    public static UiSettings Load()
    {
        try { return JsonSerializer.Deserialize<UiSettings>(File.ReadAllText(Path.Combine(DataDirectory, "desktop-ui.json"))) ?? new(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException) { return new(); }
    }
    public void Save()
    {
        try
        {
            Directory.CreateDirectory(DataDirectory);
            var file = Path.Combine(DataDirectory, "desktop-ui.json");
            var temp = file + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
            File.Move(temp, file, true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { System.Diagnostics.Trace.WriteLine(ex); }
    }
}
