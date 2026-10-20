using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace FieldKit.Core;

public static partial class Analyzer
{
    public static async Task<Report> TraceAsync(TraceOptions options, CancellationToken cancellationToken = default)
    {
        var host = Inputs.Host(options.Host);
        Inputs.Range(options.MaxHops, 1, 64, "Maximum hops");
        Inputs.Range(options.TimeoutMs, 100, 5000, "Hop timeout in milliseconds");
        var windows = OperatingSystem.IsWindows();
        var command = windows ? "tracert" : "traceroute";
        var arguments = windows ? new[] { "-d", "-h", options.MaxHops.ToString(CultureInfo.InvariantCulture), "-w", options.TimeoutMs.ToString(CultureInfo.InvariantCulture), host }
            : new[] { "-n", "-m", options.MaxHops.ToString(CultureInfo.InvariantCulture), "-w", (options.TimeoutMs / 1000.0).ToString("0.###", CultureInfo.InvariantCulture), "-q", "1", host };
        ProcessResult result;
        try { result = await Commands.RunAsync(command, arguments, TimeSpan.FromSeconds(Math.Min(360, options.MaxHops * options.TimeoutMs / 1000.0 * (windows ? 3 : 1) + 15)), cancellationToken).ConfigureAwait(false); }
        catch (Win32Exception)
        {
            return Report.Create("trace", $"Route · {host}", ["Status", "Details"],
                new[] { new[] { "Unavailable", windows ? "Windows tracert could not be started." : "Install your distribution's traceroute package, then run this tool again." } },
                "Traceroute uses the operating system utility. It requires no app-managed raw socket or elevated app session.");
        }
        var rows = new List<List<string>>();
        foreach (var line in result.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var firstSpace = line.IndexOfAny([' ', '\t']);
            if (firstSpace > 0 && int.TryParse(line[..firstSpace], out var hop)) rows.Add([hop.ToString(CultureInfo.InvariantCulture), line[(firstSpace + 1)..].Trim()]);
            else rows.Add(["—", line]);
        }
        if (!string.IsNullOrWhiteSpace(result.Error)) rows.Add(["Message", result.Error.Trim()]);
        return Report.Create("trace", $"Route · {host}", ["Hop", "Observed result"], rows,
            $"{command} exit status: {result.ExitCode}. Asterisks indicate missing replies, not a confirmed broken hop.",
            "The OS route and VPN policy apply. Some routers and firewalls do not answer traceroute probes.");
    }

    public static async Task<Report> WifiAsync(CancellationToken cancellationToken = default)
    {
        if (OperatingSystem.IsWindows())
        {
            try
            {
                var result = await Commands.RunAsync("netsh", ["wlan", "show", "interfaces"], TimeSpan.FromSeconds(12), cancellationToken).ConfigureAwait(false);
                var rows = new List<List<string>>();
                foreach (var line in result.Output.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
                {
                    var split = line.IndexOf(':');
                    if (split > 0) rows.Add([line[..split].Trim(), line[(split + 1)..].Trim()]);
                    else if (rows.Count == 0 || line.Contains("denied", StringComparison.OrdinalIgnoreCase) || line.Contains("location", StringComparison.OrdinalIgnoreCase)) rows.Add(["System message", line]);
                }
                if (!string.IsNullOrWhiteSpace(result.Error)) rows.Add(["System message", result.Error.Trim()]);
                if (rows.Count == 0) rows.Add(["Wi-Fi", "No interface information was returned."]);
                return Report.Create("wifi", "Wi-Fi signal snapshot", ["Property", "Observed value"], rows,
                    $"Windows WLAN service · command exit status {result.ExitCode} · captured {DateTimeOffset.Now:g}",
                    "Signal is the percentage reported by Windows, not a measured distance. Windows privacy settings may restrict WLAN details.",
                    "Saved observations remain visible after closing. Refresh to take a new measurement.");
            }
            catch (Win32Exception) { return WifiUnavailable("Windows netsh could not be started."); }
        }
        if (OperatingSystem.IsLinux())
        {
            try
            {
                var result = await Commands.RunAsync("nmcli", ["-t", "-e", "yes", "-f", "IN-USE,SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY,DEVICE", "device", "wifi", "list", "--rescan", "no"], TimeSpan.FromSeconds(12), cancellationToken).ConfigureAwait(false);
                var rows = result.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(SplitNmcli)
                    .Where(values => values.Count == 8).Select(values => new List<string>
                    {
                        values[7], values[1].Length == 0 ? "Hidden network" : values[1], values[2],
                        values[5].Length == 0 ? "Unavailable" : values[5] + "%", $"{values[3]} · {values[4]}", values[6], values[0] == "*" ? "Connected" : "Observed"
                    }).ToList();
                if (rows.Count == 0) return WifiUnavailable(result.Error.Length > 0 ? result.Error.Trim() : "NetworkManager returned no Wi-Fi observations. The radio may be disconnected, disabled or unmanaged.");
                return Report.Create("wifi", "Wi-Fi signal snapshot", ["Interface", "Network", "BSSID", "Signal", "Channel / frequency", "Security", "Status"], rows,
                    "Source: NetworkManager nmcli cache. Refresh does not force a wireless scan or disconnect an interface.",
                    "Signal is an OS-reported percentage, not distance. The observation cache can be older than this snapshot.");
            }
            catch (Win32Exception) { return WifiUnavailable("NetworkManager nmcli is not installed. Install it or use your distribution's Wi-Fi tool. Other diagnostics remain available."); }
        }
        return WifiUnavailable("Wi-Fi signal collection is available on Windows with WLAN and Linux with NetworkManager.");
    }

    private static Report WifiUnavailable(string detail) => Report.Create("wifi", "Wi-Fi signal snapshot", ["Status", "Details"],
        new[] { new[] { "Unavailable", detail } }, "No signal value has been invented or estimated.");

    internal static List<string> SplitNmcli(string line)
    {
        var result = new List<string>(); var text = new StringBuilder(); var escaped = false;
        foreach (var c in line.TrimEnd('\r'))
        {
            if (escaped) { text.Append(c); escaped = false; }
            else if (c == '\\') escaped = true;
            else if (c == ':') { result.Add(text.ToString()); text.Clear(); }
            else text.Append(c);
        }
        if (escaped) text.Append('\\');
        result.Add(text.ToString()); return result;
    }

    public static byte[] MagicPacket(string macAddress)
    {
        var compact = macAddress.Replace(":", "", StringComparison.Ordinal).Replace("-", "", StringComparison.Ordinal).Replace(".", "", StringComparison.Ordinal).Trim();
        if (compact.Length != 12 || !compact.All(Uri.IsHexDigit)) throw new ArgumentException("Enter a six-byte hardware address, for example AA:BB:CC:DD:EE:FF.");
        var mac = Convert.FromHexString(compact); var packet = new byte[102];
        Array.Fill(packet, (byte)255, 0, 6);
        for (var index = 0; index < 16; index++) mac.CopyTo(packet, 6 + index * 6);
        return packet;
    }

    public static async Task<Report> WakeAsync(WakeOptions options, CancellationToken cancellationToken = default)
    {
        var packet = MagicPacket(options.MacAddress);
        if (!IPAddress.TryParse(options.BroadcastAddress.Trim(), out var destination) || destination.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("Enter an IPv4 broadcast or destination address.");
        Inputs.Range(options.Port, 1, 65535, "Destination port");
        using var udp = new UdpClient(AddressFamily.InterNetwork) { EnableBroadcast = true };
        var count = await udp.SendAsync(packet, new IPEndPoint(destination, options.Port), cancellationToken).ConfigureAwait(false);
        return Report.Create("wake", "Wake-on-LAN", ["Device", "Destination", "Result"],
            new[] { new[] { options.MacAddress, $"{destination}:{options.Port}", $"{count} bytes sent" } },
            "The magic packet was sent. Wake-on-LAN has no delivery acknowledgement; the target must support and enable it.");
    }

    public static async Task<Report> RdapAsync(string target, CancellationToken cancellationToken = default)
    {
        try { return await RdapCoreAsync(target, cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { throw new TimeoutException("The registration service did not answer within 20 seconds."); }
    }

    private static async Task<Report> RdapCoreAsync(string target, CancellationToken cancellationToken)
    {
        target = Inputs.Host(target);
        var addressQuery = IPAddress.TryParse(target, out _);
        var uri = new Uri($"https://rdap.org/{(addressQuery ? "ip" : "domain")}/{Uri.EscapeDataString(target)}");
        using var handler = new HttpClientHandler { AllowAutoRedirect = false };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("FieldKit/1.0.0");
        client.DefaultRequestHeaders.Accept.ParseAdd("application/rdap+json, application/json");
        HttpResponseMessage? response = null;
        for (var attempt = 0; attempt < 6; attempt++)
        {
            response?.Dispose();
            response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            if ((int)response.StatusCode is >= 300 and < 400 && response.Headers.Location is Uri redirect)
            {
                uri = redirect.IsAbsoluteUri ? redirect : new Uri(uri, redirect);
                if (uri.Scheme != "https" || !string.IsNullOrEmpty(uri.UserInfo)) throw new InvalidDataException("The RDAP service redirected to a non-HTTPS or credentialed URL.");
                continue;
            }
            break;
        }
        using (response)
        {
            if (response is null) throw new IOException("No RDAP response was received.");
            response.EnsureSuccessStatusCode();
            var content = await ReadBoundedAsync(response.Content, 2 * 1024 * 1024, cancellationToken).ConfigureAwait(false);
            using var document = JsonDocument.Parse(content, new JsonDocumentOptions { MaxDepth = 64 });
            var rows = new List<List<string>>();
            var root = document.RootElement;
            foreach (var key in new[] { "objectClassName", "handle", "ldhName", "unicodeName", "name", "type", "country", "startAddress", "endAddress", "ipVersion", "port43" })
                if (root.TryGetProperty(key, out var value) && value.ValueKind == JsonValueKind.String) rows.Add([HumanField(key), value.GetString() ?? ""]);
            if (root.TryGetProperty("status", out var statuses) && statuses.ValueKind == JsonValueKind.Array)
                rows.Add(["Status", string.Join(", ", statuses.EnumerateArray().Select(v => v.ToString()))]);
            if (root.TryGetProperty("nameservers", out var servers) && servers.ValueKind == JsonValueKind.Array)
                foreach (var server in servers.EnumerateArray()) if (server.TryGetProperty("ldhName", out var name)) rows.Add(["Nameserver", name.ToString()]);
            if (root.TryGetProperty("events", out var events) && events.ValueKind == JsonValueKind.Array)
                foreach (var entry in events.EnumerateArray())
                    if (entry.TryGetProperty("eventAction", out var action) && entry.TryGetProperty("eventDate", out var date)) rows.Add([action.ToString(), date.ToString()]);
            if (root.TryGetProperty("remarks", out var remarks) && remarks.ValueKind == JsonValueKind.Array)
                foreach (var remark in remarks.EnumerateArray())
                    if (remark.TryGetProperty("description", out var text) && text.ValueKind == JsonValueKind.Array) rows.Add(["Registry remark", string.Join("\n", text.EnumerateArray().Select(t => t.ToString()))]);
            return Report.Create("rdap", $"Registration · {target}", ["Property", "Value"], rows,
                $"Source: {uri}. RDAP bootstrap: rdap.org.", "Only registry-published registration information is shown. This does not identify the user of an IP address.");
        }
    }

    private static string HumanField(string field) => field switch
    {
        "objectClassName" => "Record type", "ldhName" => "Domain", "unicodeName" => "International domain", "startAddress" => "First address",
        "endAddress" => "Last address", "ipVersion" => "IP version", "port43" => "WHOIS server", _ => char.ToUpperInvariant(field[0]) + field[1..]
    };

    internal static async Task<byte[]> ReadBoundedAsync(HttpContent content, int maximum, CancellationToken token)
    {
        if (content.Headers.ContentLength > maximum) throw new InvalidDataException("The response is larger than the supported size.");
        await using var stream = await content.ReadAsStreamAsync(token).ConfigureAwait(false);
        using var result = new MemoryStream();
        var buffer = new byte[8192];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, token).ConfigureAwait(false);
            if (read == 0) break;
            if (result.Length + read > maximum) throw new InvalidDataException("The response is larger than the supported size.");
            result.Write(buffer, 0, read);
        }
        return result.ToArray();
    }
}

internal sealed record ProcessResult(int ExitCode, string Output, string Error);

internal static class Commands
{
    public static async Task<ProcessResult> RunAsync(string executable, IEnumerable<string> arguments, TimeSpan timeout, CancellationToken token)
    {
        var info = new ProcessStartInfo(executable) { UseShellExecute = false, RedirectStandardOutput = true,
            RedirectStandardError = true, CreateNoWindow = true };
        foreach (var argument in arguments) info.ArgumentList.Add(argument);
        if (!OperatingSystem.IsWindows()) info.Environment["LC_ALL"] = "C";
        using var process = new Process { StartInfo = info };
        process.Start();
        var stdout = ReadOutputAsync(process.StandardOutput, token);
        var stderr = ReadOutputAsync(process.StandardError, token);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(timeout);
        try
        {
            await process.WaitForExitAsync(deadline.Token).ConfigureAwait(false);
            return new(process.ExitCode, await stdout.ConfigureAwait(false), await stderr.ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(true); } catch (InvalidOperationException) { }
            if (token.IsCancellationRequested) throw;
            throw new TimeoutException($"{executable} did not finish within {timeout.TotalSeconds:0} seconds.");
        }
    }

    private static async Task<string> ReadOutputAsync(StreamReader reader, CancellationToken token)
    {
        var result = new StringBuilder(); var buffer = new char[4096];
        while (true)
        {
            var count = await reader.ReadAsync(buffer.AsMemory(), token).ConfigureAwait(false);
            if (count == 0) break;
            if (result.Length < 1024 * 1024) result.Append(buffer, 0, Math.Min(count, 1024 * 1024 - result.Length));
        }
        return result.ToString();
    }
}
