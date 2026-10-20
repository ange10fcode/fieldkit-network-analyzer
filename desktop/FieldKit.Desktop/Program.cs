using Avalonia;
using FieldKit.Core;
using System.Text.Json;

namespace FieldKit.Desktop;

internal static class Program
{
    internal static string[] Arguments { get; private set; } = [];
    [STAThread]
    public static int Main(string[] args)
    {
        Arguments = args;
        var dataIndex = Array.IndexOf(args, "--data-dir");
        if (dataIndex >= 0 && dataIndex + 1 < args.Length) UiSettings.DataRootOverride = Path.GetFullPath(args[dataIndex + 1]);
        if (args.Contains("--smoke-test")) return SmokeTest().GetAwaiter().GetResult();
        if (args.Contains("--version")) { Console.WriteLine("FieldKit 1.0.0"); return 0; }
        try { return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args); }
        catch (Exception ex) { Console.Error.WriteLine(ex); return 1; }
    }

    public static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<App>().UsePlatformDetect().WithInterFont().LogToTrace();

    private static async Task<int> SmokeTest()
    {
        var directory = Path.Combine(Path.GetTempPath(), "fieldkit-smoke-" + Guid.NewGuid().ToString("N"));
        try
        {
            var networks = await Analyzer.GetNetworksAsync();
            var store = new ReportStore(directory);
            var report = Report.Create("smoke", "Persistence check", ["Result"], new[] { new[] { "Verified" } }, "No network probes sent.");
            await store.SaveAsync(report);
            var restored = await store.LoadLatestAsync("smoke");
            if (restored?.Rows.FirstOrDefault()?.FirstOrDefault() != "Verified") throw new InvalidOperationException("Report persistence failed.");
            Console.WriteLine(JsonSerializer.Serialize(new { app = "FieldKit", version = "1.0.0", runtime = Environment.Version.ToString(), platform = System.Runtime.InteropServices.RuntimeInformation.OSDescription, interfaces = networks.Count, persistence = "passed" }));
            return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine(ex.ToString()); return 1; }
        finally { try { Directory.Delete(directory, true); } catch (IOException) { } catch (UnauthorizedAccessException) { } }
    }
}
