using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using FieldKit.Core;

var checks = new Checks();
await checks.RunAsync();
Console.WriteLine($"PASS · {checks.Count} checks · loopback network fixtures only · {System.Runtime.InteropServices.RuntimeInformation.OSDescription}");

sealed class Checks
{
    public int Count { get; private set; }
    private void That(bool condition, string description)
    {
        Count++;
        if (!condition) throw new InvalidOperationException($"FAIL: {description}");
    }
    private void Throws<T>(Action action, string description) where T : Exception
    {
        try { action(); } catch (T) { That(true, description); return; }
        That(false, description);
    }
    private async Task ThrowsAsync<T>(Func<Task> action, string description) where T : Exception
    {
        try { await action(); } catch (T) { That(true, description); return; }
        That(false, description);
    }

    public async Task RunAsync()
    {
        InputsAndEvidence();
        await TcpAndLanAsync();
        await DnsAsync();
        await SsdpAsync();
        await WakeAsync();
        await PersistenceAsync();
        await CancellationAsync();
    }

    private void InputsAndEvidence()
    {
        That(Inputs.LanTargets("192.168.4.19/24").Count == 254, "CIDR normalizes to subnet and omits network/broadcast");
        That(Inputs.LanTargets("192.168.4.19/24")[0].ToString() == "192.168.4.1", "CIDR begins at first usable host");
        That(Inputs.LanTargets("192.168.4.19/31").Select(a => a.ToString()).SequenceEqual(["192.168.4.18", "192.168.4.19"]), "/31 preserves both endpoints");
        That(Inputs.LanTargets("127.0.0.1").Single().Equals(IPAddress.Loopback), "literal address is a single target");
        That(Inputs.LanTargets("10.0.0.0/20").Count == 4094, "largest allowed subnet remains bounded");
        foreach (var bad in new[] { "10.0.0.0/19", "::1/128", "10.0.0.1/33", "example.com", "10.0.0.1/24/1", "" })
            Throws<ArgumentException>(() => Inputs.LanTargets(bad), $"reject unsupported LAN target {bad}");
        That(Inputs.Ports("80,80,81-83, 443").SequenceEqual([80, 81, 82, 83, 443]), "ports deduplicate and expand ranges");
        That(Inputs.Ports(null).Length == 18, "common ports are explicit 18-port profile");
        foreach (var bad in new[] { "0", "65536", "90-80", "1-65535", "1;echo", ",", "-1", "80--81" })
            Throws<ArgumentException>(() => Inputs.Ports(bad), $"reject invalid ports {bad}");
        That(Inputs.Host("[::1]") == "::1", "IPv6 brackets normalize without port ambiguity");
        That(Inputs.Host("bücher.example") == "xn--bcher-kva.example", "international hostname uses IDNA");
        That(Inputs.DnsName("_ipp._tcp.example.") == "_ipp._tcp.example", "DNS service name accepts underscores");
        foreach (var bad in new[] { "https://example.com", "-h", "a;echo", "a b", "a@b", "a\\b", "" })
            Throws<ArgumentException>(() => Inputs.Host(bad), $"reject unsafe target {bad}");
        Throws<ArgumentException>(() => Inputs.Source("0.0.0.0"), "wildcard is not an explicit source");
        var fixture = new NetworkProfile("id", "Wi-Fi", "Test", "Wi-Fi", "Up", "AA:BB:CC:DD:EE:FF",
            [new("192.0.2.3", 24, "IPv4"), new("2001:db8::3", 64, "IPv6")], ["192.0.2.1"], ["192.0.2.53"], true, true, 1000000000);
        var vpn = fixture with { Id = "vpn", Name = "Tailscale", Kind = "VPN / tunnel", Addresses = [new("100.64.0.1", 32, "IPv4")] };
        var report = Analyzer.NetworkReport([fixture, vpn]);
        That(report.Rows.Count == 2, "inventory keeps physical and VPN adapters separately");
        That(report.Rows[0][3].Contains("2001:db8::3/64") && report.Rows[1][3] == "100.64.0.1/32", "IPv6 and VPN address do not overwrite IPv4");
        That(report.Summary.Any(s => s.Contains("does not prove")), "gateway presence is not mislabeled default route");
        var fields = Analyzer.SplitNmcli("*:Lab\\:Net:AA\\:BB\\:CC\\:DD\\:EE\\:FF:36:5180 MHz:82:WPA2:wlan0");
        That(fields.Count == 8 && fields[1] == "Lab:Net" && fields[2] == "AA:BB:CC:DD:EE:FF", "nmcli escaped colons preserve network and BSSID");
    }

    private async Task TcpAndLanAsync()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var closedListener = new TcpListener(IPAddress.Loopback, 0); closedListener.Start();
        var closed = ((IPEndPoint)closedListener.LocalEndpoint).Port; closedListener.Stop();
        var report = await Analyzer.ScanPortsAsync(new("127.0.0.1", $"{port},{closed}", 300));
        That(report.Rows.Single(r => r[0] == $"{port}/TCP")[2] == "Open", "actual loopback TCP listener is open");
        var closedRow = report.Rows.Single(r => r[0] == $"{closed}/TCP");
        That(closedRow[2] is "Closed" or "No response" && closedRow[5].Length > 0,
            "unused loopback port is not open; OS/firewall may refuse or silently drop it: " + string.Join(" | ", closedRow));
        That(report.Summary.Any(s => s.Contains("not identified software")), "port hints are not asserted device names");
        var lan = await Analyzer.ScanLanAsync(new("127.0.0.1", port.ToString(), 300, 1, "127.0.0.1", false));
        That(lan.Rows.Count == 1 && lan.Rows[0][1] == "127.0.0.1", "bound LAN probe discovers only requested loopback host");
        That(lan.Rows[0][3].Contains(port.ToString()) && lan.Rows[0][2].Contains("TCP open"), "LAN open-port tag has a successful TCP handshake");
        That(lan.Rows[0][0] == "Unnamed device", "disabled/unpublished name is not invented");
        That(!lan.Rows[0][2].Contains("Bluetooth") && !lan.Rows[0][2].Contains("IPv6"), "IP response does not invent Bluetooth or IPv6 correlation");
        That(lan.Summary.Any(s => s.Contains("ICMP is omitted")), "explicit source never silently uses unbound ICMP");
        var invalid = await Analyzer.ScanPortsAsync(new("127.0.0.1", port.ToString(), 300, 1, "192.0.2.77"));
        That(invalid.Rows.Single()[2] == "Source unavailable", "invalid source binding is a visible failure without fallback");
        var ping = await Analyzer.PingAsync(new("127.0.0.1", 1, 300, 0));
        That(ping.Rows.Count == 1 && ping.Rows[0][2] == "ICMP", "ping reports actual ICMP attempt");
        That(ping.Rows[0][3] == "Reply" || ping.Rows[0][5].Length > 0, "OS ICMP failure has details instead of a fake reply");
    }

    private async Task DnsAsync()
    {
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var endpoint = (IPEndPoint)udp.Client.LocalEndPoint!;
        var server = Task.Run(async () =>
        {
            var query = await udp.ReceiveAsync();
            await udp.SendAsync(Answer(query.Buffer), query.RemoteEndPoint);
        });
        var result = await DnsWire.QueryAsync("fixture.example", "A", endpoint, 1500);
        await server;
        That(result.Answers.Single().Value == "192.0.2.44" && result.Answers[0].Ttl == 60, "actual UDP DNS answer parses address and TTL");
        That(result.Transport == "UDP" && result.Status == "Success", "UDP result states actual transport and rcode");

        using var tcp = new TcpListener(IPAddress.Loopback, 0); tcp.Start();
        var fallbackEndpoint = (IPEndPoint)tcp.LocalEndpoint;
        using var truncatedUdp = new UdpClient(fallbackEndpoint);
        var fallbackServer = Task.Run(async () =>
        {
            var query = await truncatedUdp.ReceiveAsync();
            var truncated = query.Buffer.ToArray(); truncated[2] = 0x83; truncated[3] = 0x80;
            await truncatedUdp.SendAsync(truncated, query.RemoteEndPoint);
            using var connection = await tcp.AcceptTcpClientAsync(); var stream = connection.GetStream();
            var length = new byte[2]; await stream.ReadExactlyAsync(length);
            var request = new byte[BinaryPrimitives.ReadUInt16BigEndian(length)]; await stream.ReadExactlyAsync(request);
            var reply = Answer(request); var frame = new byte[reply.Length + 2];
            BinaryPrimitives.WriteUInt16BigEndian(frame, (ushort)reply.Length); reply.CopyTo(frame, 2); await stream.WriteAsync(frame);
        });
        var fallback = await DnsWire.QueryAsync("fixture.example", "A", fallbackEndpoint, 2000);
        await fallbackServer;
        That(fallback.Transport.StartsWith("TCP") && fallback.Answers.Single().Value == "192.0.2.44", "truncated UDP retries actual length-framed TCP query");

        using var wrongUdp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var wrongServer = Task.Run(async () => { var query = await wrongUdp.ReceiveAsync(); var reply = Answer(query.Buffer); reply[0] ^= 1; await wrongUdp.SendAsync(reply, query.RemoteEndPoint); });
        await ThrowsAsync<InvalidDataException>(async () => await DnsWire.QueryAsync("fixture.example", "A", (IPEndPoint)wrongUdp.Client.LocalEndPoint!, 1500), "reject DNS response with wrong transaction ID");
        await wrongServer;
        using var timeoutUdp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        await ThrowsAsync<TimeoutException>(async () => await DnsWire.QueryAsync("fixture.example", "A", (IPEndPoint)timeoutUdp.Client.LocalEndPoint!, 100), "DNS timeout is a timeout rather than user cancellation");
        var malformed = Answer([0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, (byte)'x', 0, 0, 1, 0, 1]);
        var position = malformed.Length - 16; malformed[position] = 0xC0; malformed[position + 1] = (byte)position;
        Throws<InvalidDataException>(() => DnsWire.Parse(malformed, "x", 1, 1, "test"), "reject cyclic compression pointer");
        var system = await Analyzer.DnsAsync(new("localhost", "A"));
        That(system.Rows.Any(r => IPAddress.TryParse(r[2], out var ip) && IPAddress.IsLoopback(ip)), "system resolver returns real localhost address");
    }

    private static byte[] Answer(byte[] query)
    {
        var result = new byte[query.Length + 16]; query.CopyTo(result, 0);
        result[2] = 0x81; result[3] = 0x80; result[6] = 0; result[7] = 1;
        var answer = result.AsSpan(query.Length); answer[0] = 0xC0; answer[1] = 0x0C;
        answer[3] = 1; answer[5] = 1; answer[9] = 60; answer[11] = 4;
        answer[12] = 192; answer[13] = 0; answer[14] = 2; answer[15] = 44;
        return result;
    }

    private async Task SsdpAsync()
    {
        using var http = new TcpListener(IPAddress.Loopback, 0); http.Start();
        var port = ((IPEndPoint)http.LocalEndpoint).Port;
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var udpEndpoint = (IPEndPoint)udp.Client.LocalEndPoint!;
        var fixture = Task.Run(async () =>
        {
            var request = await udp.ReceiveAsync();
            var response = Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nLOCATION: http://127.0.0.1:{port}/device.xml\r\nST: upnp:rootdevice\r\n\r\n");
            await udp.SendAsync(response, request.RemoteEndPoint);
            using var client = await http.AcceptTcpClientAsync(); var stream = client.GetStream();
            var buffer = new byte[4096]; _ = await stream.ReadAsync(buffer);
            var xml = Encoding.UTF8.GetBytes("<?xml version=\"1.0\"?><root xmlns=\"urn:schemas-upnp-org:device-1-0\"><device><friendlyName>Lab &amp; printer</friendlyName></device></root>");
            var header = Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {xml.Length}\r\nConnection: close\r\n\r\n");
            await stream.WriteAsync(header); await stream.WriteAsync(xml);
        });
        var found = await SsdpDiscovery.FindAsync([IPAddress.Loopback], default, null, udpEndpoint, 200);
        await fixture.WaitAsync(TimeSpan.FromSeconds(8));
        That(found.Single().Name == "Lab & printer" && found[0].Address == "127.0.0.1", "actual SSDP reply and HTTP XML produce published friendly name");
        That(found[0].Evidence.Contains("ports not inferred open"), "advertised service never claims confirmed TCP ports");
        That(!SsdpDiscovery.ValidLocation(new("http://192.168.1.8/device.xml"), IPAddress.Loopback), "description cannot target a different address");
        That(!SsdpDiscovery.ValidLocation(new("http://example.com/device.xml"), IPAddress.Loopback), "description cannot use a DNS name");
        That(!SsdpDiscovery.ValidLocation(new("http://8.8.8.8/device.xml"), IPAddress.Parse("8.8.8.8")), "description cannot fetch public address");
        That(!SsdpDiscovery.ValidLocation(new("file:///etc/passwd"), IPAddress.Loopback), "description cannot use file scheme");
        That(!SsdpDiscovery.ValidLocation(new("http://user:pass@127.0.0.1/device.xml"), IPAddress.Loopback), "description cannot carry credentials");
        await ThrowsAsync<System.Xml.XmlException>(async () => await DescriptionAsync("<!DOCTYPE root [<!ENTITY ex SYSTEM 'http://127.0.0.1:1/no-request'>]><root><device><friendlyName>&ex;</friendlyName></device></root>"), "actual HTTP description rejects external entities and DTDs");
        That(await DescriptionAsync("<root><device><modelName>Model only</modelName></device></root>") is null, "model name is not invented as a published friendly name");
        await ThrowsAsync<InvalidDataException>(async () => await DescriptionAsync("", 300000), "description content size is bounded before download");
    }

    private static async Task<string?> DescriptionAsync(string xml, int? declaredSize = null)
    {
        using var http = new TcpListener(IPAddress.Loopback, 0); http.Start();
        var port = ((IPEndPoint)http.LocalEndpoint).Port;
        var fixture = Task.Run(async () =>
        {
            using var client = await http.AcceptTcpClientAsync(); var stream = client.GetStream();
            var request = new byte[4096]; _ = await stream.ReadAsync(request);
            var bytes = Encoding.UTF8.GetBytes(xml);
            var header = Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Length: {declaredSize ?? bytes.Length}\r\nConnection: close\r\n\r\n");
            await stream.WriteAsync(header); await stream.WriteAsync(bytes);
        });
        try { return await SsdpDiscovery.ReadDescriptionAsync(new($"http://127.0.0.1:{port}/device.xml"), IPAddress.Loopback, null, default); }
        finally { await fixture.WaitAsync(TimeSpan.FromSeconds(8)); }
    }

    private async Task WakeAsync()
    {
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)udp.Client.LocalEndPoint!).Port;
        var report = await Analyzer.WakeAsync(new("00:11:22:33:44:55", "127.0.0.1", port));
        var received = await udp.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(2));
        That(received.Buffer.Length == 102 && received.Buffer.Take(6).All(b => b == 255), "actual UDP WOL packet includes synchronization bytes");
        That(Enumerable.Range(0, 16).All(i => received.Buffer.Skip(6 + i * 6).Take(6).SequenceEqual(new byte[] { 0, 17, 34, 51, 68, 85 })), "magic packet repeats exact target MAC sixteen times");
        That(report.Summary.Any(s => s.Contains("no delivery acknowledgement")), "packet send is not falsely reported as device awake");
        Throws<ArgumentException>(() => Analyzer.MagicPacket("00:11:22"), "reject incomplete MAC");
    }

    private async Task PersistenceAsync()
    {
        var directory = Path.Combine(Path.GetTempPath(), "fieldkit-core-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var store = new ReportStore(directory);
            var captured = DateTimeOffset.UtcNow.AddHours(-2);
            var lan = new Report("lan", "LAN · saved", captured, ["Name", "Address"], [["=danger,\"quoted\"\nline", "127.0.0.1"]], ["Saved observation"]);
            await store.SaveAsync(lan);
            var wifi = Report.Create("wifi", "Signal", ["Signal"], new[] { new[] { "76%" } });
            await new ReportStore(directory).SaveAsync(wifi);
            var restored = await new ReportStore(directory).LoadLatestAsync("lan");
            That(restored?.Rows[0][0] == lan.Rows[0][0] && restored.CreatedAt == captured, "new store instance retains full report and original observation age");
            That((await store.LoadLatestAsync("wifi"))?.Rows[0][0] == "76%", "signal and LAN retained independently");
            That((await store.LoadHistoryAsync()).Count == 2, "history retains distinct observations");
            var csv = ReportStore.ExportCsv(lan);
            That(csv.Contains("\"'=danger,\"\"quoted\"\"\nline\""), "CSV escapes multiline quotes and neutralizes spreadsheet formulas");
            var json = ReportStore.ExportJson(lan);
            That(JsonSerializer.Deserialize<Report>(json)?.Rows[0][0] == lan.Rows[0][0], "JSON export preserves exact original text");
            await store.SaveFavoritesAsync([new("Loopback", "ports", "127.0.0.1", "443")]);
            That((await new ReportStore(directory).FavoritesAsync()).Single().Target == "127.0.0.1", "favorites persist across instances");
            await Task.WhenAll(Enumerable.Range(0, 8).Select(i => new ReportStore(directory).SaveAsync(wifi with { Title = $"Concurrent {i}" })));
            That((await store.LoadHistoryAsync()).Count == 10 && (await store.LoadLatestAsync("wifi")) is not null, "concurrent writers retain complete atomic documents");
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            await ThrowsAsync<OperationCanceledException>(() => store.SaveAsync(lan with { Title = "Should not replace" }, cancelled.Token), "cancelled write does not replace retained report");
            That((await store.LoadLatestAsync("lan"))?.Title == "LAN · saved", "prior observation survives cancelled write");
            await File.WriteAllTextAsync(Path.Combine(directory, "latest-lan.json"), "{broken");
            That(await store.LoadLatestAsync("lan") is null, "corrupt saved observation is ignored safely");
            await ThrowsAsync<ArgumentException>(async () => await store.LoadLatestAsync("../outside"), "saved tool key cannot traverse outside directory");
            await store.ClearHistoryAsync();
            That((await store.LoadHistoryAsync()).Count == 0 && await store.LoadLatestAsync("wifi") is not null, "clearing history preserves retained tool observations");
            await store.ClearLatestAsync("wifi");
            That(await store.LoadLatestAsync("wifi") is null && (await store.FavoritesAsync()).Count == 1, "clear retained view does not delete favorites");
            That(!Directory.EnumerateFiles(directory, "*.tmp", SearchOption.AllDirectories).Any(), "atomic writer leaves no temporary files after successful/cancelled writes");
        }
        finally { Directory.Delete(directory, true); }
    }

    private async Task CancellationAsync()
    {
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await ThrowsAsync<OperationCanceledException>(async () => await Analyzer.ScanPortsAsync(new("127.0.0.1", "80"), cancelled.Token), "port scan respects cancellation");
        await ThrowsAsync<OperationCanceledException>(async () => await Analyzer.ScanLanAsync(new("127.0.0.1", "80", ResolveNames: false), cancelled.Token), "LAN scan respects cancellation");
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        await ThrowsAsync<OperationCanceledException>(async () => await DnsWire.QueryAsync("fixture.example", "A", (IPEndPoint)udp.Client.LocalEndPoint!, 1000, cancelled.Token), "DNS respects user cancellation separately from timeout");
        using var liveCancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        await ThrowsAsync<OperationCanceledException>(async () => await DnsWire.QueryAsync("fixture.example", "A", (IPEndPoint)udp.Client.LocalEndPoint!, 3000, liveCancellation.Token), "user cancellation interrupts an outstanding UDP receive");
        await ThrowsAsync<ArgumentException>(async () => await Analyzer.ScanPortsAsync(new("127.0.0.1", "80", Concurrency: 33)), "probe concurrency has a hard cap");
        await ThrowsAsync<ArgumentException>(async () => await Analyzer.DnsAsync(new("localhost", "A", TimeoutMs: -1)), "DNS timeout validates before OS lookup");
    }
}
