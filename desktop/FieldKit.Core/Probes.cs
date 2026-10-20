using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace FieldKit.Core;

public static partial class Analyzer
{
    private sealed record ProbeResult(int Port, string Status, double ElapsedMs, string Detail)
    {
        public bool Reached => Status is "Open" or "Closed";
    }

    public static async Task<Report> ScanLanAsync(LanScanOptions options, CancellationToken cancellationToken = default,
        IProgress<Report>? progress = null)
    {
        var targets = Inputs.LanTargets(options.Target);
        Inputs.Range(options.TimeoutMs, 100, 10000, "Probe timeout in milliseconds");
        Inputs.Range(options.Concurrency, 1, 32, "Concurrency");
        var ports = Inputs.Ports(options.Ports);
        var source = Inputs.Source(options.SourceAddress);
        if (source?.AddressFamily == AddressFamily.InterNetworkV6) throw new ArgumentException("An IPv4 LAN scan needs an IPv4 source address.");
        var created = DateTimeOffset.UtcNow;
        var rows = new ConcurrentDictionary<string, List<string>>();
        var networks = GetNetworks();
        var self = networks.SelectMany(n => n.Addresses).Select(a => a.Address).ToHashSet(StringComparer.Ordinal);
        var gateways = networks.SelectMany(n => n.Gateways).ToHashSet(StringComparer.Ordinal);
        var completed = 0;
        var nameCount = 0;
        var bindingFailures = 0;
        var custom = !string.IsNullOrWhiteSpace(options.Ports);
        var gate = new object();
        Report Snapshot(bool final) => new("lan", $"LAN devices · {options.Target}", created,
            ["Name", "Address", "Capabilities", "Open ports", "Response", "Evidence"],
            rows.OrderBy(p => AddressSort(p.Key)).Select(p => p.Value).ToList(),
            [$"{Volatile.Read(ref completed):N0} of {targets.Count:N0} addresses checked · {rows.Count:N0} responding devices{(final ? " · complete" : "")}",
             source is null ? "Routing: operating system default. VPN policy applies." : $"TCP source: {source}. ICMP is omitted because this platform API cannot bind a source address.",
             "IPv4, gateway and this-computer tags are observed locally. Bluetooth and additional IPv6 addresses are unknown for IP-only devices.",
             "Names come from reverse DNS or local UPnP advertisements. An unnamed device did not publish a usable name.",
             $"{Volatile.Read(ref bindingFailures):N0} TCP probes encountered a source-binding or permission error. No forced bypass was attempted."]);
        await Parallel.ForEachAsync(targets, new ParallelOptions { MaxDegreeOfParallelism = options.Concurrency, CancellationToken = cancellationToken },
            async (address, token) =>
            {
                var evidence = new List<string>();
                var isSelf = self.Contains(address.ToString());
                var reachable = isSelf;
                var elapsed = 0.0;
                if (isSelf) evidence.Add("Address belongs to this computer");
                if (source is null)
                {
                    var ping = await IcmpAsync(address, options.TimeoutMs, token).ConfigureAwait(false);
                    if (ping.Status == "Reply")
                    {
                        reachable = true;
                        elapsed = ping.ElapsedMs;
                        evidence.Add("ICMP echo reply");
                    }
                }
                var open = new List<int>();
                var probePorts = custom || reachable ? ports : new[] { 80, 443, 445, 22 };
                var probed = new HashSet<int>();
                foreach (var port in probePorts)
                {
                    token.ThrowIfCancellationRequested();
                    var probe = await TcpAsync(address, port, source, options.TimeoutMs, token).ConfigureAwait(false);
                    probed.Add(port);
                    if (probe.Status == "Open") open.Add(port);
                    if (probe.Reached)
                    {
                        reachable = true;
                        if (elapsed == 0) elapsed = probe.ElapsedMs;
                    }
                    if (probe.Status == "Source unavailable") Interlocked.Increment(ref bindingFailures);
                }
                if (reachable && !custom)
                {
                    foreach (var port in ports.Where(port => !probed.Contains(port)))
                    {
                        var probe = await TcpAsync(address, port, source, options.TimeoutMs, token).ConfigureAwait(false);
                        if (probe.Status == "Open") open.Add(port);
                    }
                }
                if (reachable)
                {
                    var name = "";
                    if (options.ResolveNames && Interlocked.Increment(ref nameCount) <= 128)
                    {
                        try
                        {
                            var entry = await Dns.GetHostEntryAsync(address).WaitAsync(TimeSpan.FromMilliseconds(Math.Min(1500, options.TimeoutMs * 2)), token).ConfigureAwait(false);
                            if (!IPAddress.TryParse(entry.HostName, out _) && !string.IsNullOrWhiteSpace(entry.HostName))
                            {
                                name = entry.HostName.TrimEnd('.');
                                evidence.Add("Name: system reverse DNS");
                            }
                        }
                        catch (Exception e) when (e is SocketException or TimeoutException or ArgumentException) { }
                    }
                    var tags = new List<string> { "IPv4" };
                    if (gateways.Contains(address.ToString())) tags.Add("Gateway");
                    if (isSelf) tags.Add("This computer");
                    if (open.Count > 0) { tags.Add("TCP open"); evidence.Add("Confirmed TCP connection"); }
                    else if (!evidence.Any(e => e.Contains("ICMP")) && !isSelf) evidence.Add("TCP connection refused: host responded, no probed service opened");
                    rows[address.ToString()] = [name.Length == 0 ? "Unnamed device" : name, address.ToString(), string.Join(" · ", tags),
                        open.Count == 0 ? "None confirmed" : string.Join(", ", open.Order().Select(p => $"{p} {ServiceName(p)}".Trim())),
                        elapsed > 0 ? $"{elapsed:0.0} ms" : "Local address", string.Join("; ", evidence)];
                }
                if (Interlocked.Increment(ref completed) % 8 == 0 || Volatile.Read(ref completed) == targets.Count)
                    lock (gate) progress?.Report(Snapshot(false));
            }).ConfigureAwait(false);
        if (options.ResolveNames)
        {
            // Multicast advertisements are supplementary evidence; they never imply that an advertised TCP port accepted a connection.
            var names = await SsdpDiscovery.FindAsync(targets, cancellationToken, source).ConfigureAwait(false);
            foreach (var item in names)
            {
                if (!rows.TryGetValue(item.Address, out var row))
                {
                    row = [item.Name, item.Address, "IPv4 · Service advertised", "None confirmed", "UPnP response", item.Evidence];
                    rows[item.Address] = row;
                }
                else
                {
                    if (row[0] == "Unnamed device") row[0] = item.Name;
                    row[2] += " · Service advertised";
                    row[5] += "; " + item.Evidence;
                }
            }
        }
        var report = Snapshot(true);
        progress?.Report(report);
        return report;
    }

    private static uint AddressSort(string address) => System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(IPAddress.Parse(address).GetAddressBytes());

    public static async Task<Report> ScanPortsAsync(PortScanOptions options, CancellationToken cancellationToken = default,
        IProgress<Report>? progress = null)
    {
        var host = Inputs.Host(options.Host);
        var ports = Inputs.Ports(options.Ports);
        Inputs.Range(options.TimeoutMs, 100, 30000, "Probe timeout in milliseconds");
        Inputs.Range(options.Concurrency, 1, 32, "Concurrency");
        var source = Inputs.Source(options.SourceAddress);
        var addresses = await ResolveAsync(host, cancellationToken).ConfigureAwait(false);
        if (source is not null) addresses = addresses.Where(a => a.AddressFamily == source.AddressFamily).ToArray();
        if (addresses.Length == 0) throw new ArgumentException("The host has no address compatible with the selected source.");
        var rows = new ConcurrentDictionary<int, List<string>>();
        var created = DateTimeOffset.UtcNow;
        var completed = 0;
        var gate = new object();
        Report Snapshot() => new("ports", $"TCP ports · {host}", created,
            ["Port", "Service hint", "State", "Address", "Time", "Details"], rows.OrderBy(p => p.Key).Select(p => p.Value).ToList(),
            [$"{rows.Count:N0} of {ports.Length:N0} ports checked · {rows.Values.Count(r => r[2] == "Open"):N0} open",
             "Open means a TCP connection succeeded. Service names are conventional port hints, not identified software.",
             source is null ? "Routing: operating system default. Each resolved address is tried until a conclusive response." : $"TCP source: {source}. No fallback to another source."]);
        await Parallel.ForEachAsync(ports, new ParallelOptions { MaxDegreeOfParallelism = options.Concurrency, CancellationToken = cancellationToken },
            async (port, token) =>
            {
                ProbeResult? result = null;
                IPAddress used = addresses[0];
                foreach (var address in addresses)
                {
                    used = address;
                    result = await TcpAsync(address, port, source, options.TimeoutMs, token).ConfigureAwait(false);
                    if (result.Reached || result.Status == "Source unavailable") break;
                }
                rows[port] = [$"{port}/TCP", ServiceName(port), result!.Status, used.ToString(), $"{result.ElapsedMs:0.0} ms", result.Detail];
                if (Interlocked.Increment(ref completed) % 16 == 0 || Volatile.Read(ref completed) == ports.Length)
                    lock (gate) progress?.Report(Snapshot());
            }).ConfigureAwait(false);
        var report = Snapshot();
        progress?.Report(report);
        return report;
    }

    private static async Task<ProbeResult> TcpAsync(IPAddress address, int port, IPAddress? source, int timeoutMs, CancellationToken token)
    {
        using var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        var clock = Stopwatch.StartNew();
        if (source is not null)
        {
            try { socket.Bind(new IPEndPoint(source, 0)); }
            catch (SocketException error) { return new(port, "Source unavailable", clock.Elapsed.TotalMilliseconds, $"Cannot bind {source}: {error.SocketErrorCode}. Select Automatic or another local address."); }
        }
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(timeoutMs);
        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, port), timeout.Token).ConfigureAwait(false);
            return new(port, "Open", clock.Elapsed.TotalMilliseconds, "TCP handshake accepted");
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        { return new(port, "No response", clock.Elapsed.TotalMilliseconds, "Timed out; filtering, packet loss or an unreachable host is possible"); }
        catch (SocketException error)
        {
            var status = error.SocketErrorCode switch
            {
                SocketError.ConnectionRefused => "Closed",
                SocketError.AccessDenied or SocketError.AddressNotAvailable => "Source unavailable",
                _ => "Unreachable"
            };
            return new(port, status, clock.Elapsed.TotalMilliseconds, error.SocketErrorCode.ToString());
        }
    }

    private static async Task<(string Status, double ElapsedMs, string Detail)> IcmpAsync(IPAddress address, int timeoutMs, CancellationToken token)
    {
        using var ping = new Ping();
        try
        {
            var result = await ping.SendPingAsync(address, timeoutMs, new byte[24]).WaitAsync(token).ConfigureAwait(false);
            return result.Status == IPStatus.Success ? ("Reply", result.RoundtripTime, "ICMP echo reply") : (result.Status.ToString(), 0, result.Status.ToString());
        }
        catch (Exception error) when (error is PingException or PlatformNotSupportedException or InvalidOperationException)
        { return ("Unavailable", 0, error.InnerException?.Message ?? error.Message); }
    }

    public static async Task<Report> PingAsync(PingOptions options, CancellationToken cancellationToken = default, IProgress<Report>? progress = null)
    {
        var host = Inputs.Host(options.Host);
        Inputs.Range(options.Count, 1, 500, "Number of samples");
        Inputs.Range(options.TimeoutMs, 100, 30000, "Timeout in milliseconds");
        Inputs.Range(options.IntervalMs, 0, 60000, "Interval in milliseconds");
        if (options.TcpFallbackPort.HasValue) Inputs.Range(options.TcpFallbackPort.Value, 1, 65535, "TCP fallback port");
        var addresses = await ResolveAsync(host, cancellationToken).ConfigureAwait(false);
        var address = addresses[0];
        var created = DateTimeOffset.UtcNow;
        var rows = new List<List<string>>();
        var replies = new List<double>();
        Report Snapshot() => new("ping", $"Ping · {host}", created, ["Sample", "Address", "Method", "Status", "Time", "Details"],
            rows.Select(r => r.ToList()).ToList(), [$"{replies.Count} ICMP replies / {rows.Count} samples" + (replies.Count == 0 ? "" : $" · min {replies.Min():0.0} / average {replies.Average():0.0} / max {replies.Max():0.0} ms"),
                "A timeout does not prove that a host is offline. TCP fallback is separately labeled and is not an ICMP latency measurement."]);
        for (var sample = 1; sample <= options.Count; sample++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var result = await IcmpAsync(address, options.TimeoutMs, cancellationToken).ConfigureAwait(false);
            if (result.Status == "Reply") replies.Add(result.ElapsedMs);
            rows.Add([sample.ToString(), address.ToString(), "ICMP", result.Status, result.Status == "Reply" ? $"{result.ElapsedMs:0.0} ms" : "—", result.Detail]);
            if (result.Status != "Reply" && options.TcpFallbackPort is int port)
            {
                var tcp = await TcpAsync(address, port, null, options.TimeoutMs, cancellationToken).ConfigureAwait(false);
                rows[^1][2] = $"TCP {port} fallback";
                rows[^1][3] = tcp.Status;
                rows[^1][4] = $"{tcp.ElapsedMs:0.0} ms";
                rows[^1][5] = $"ICMP: {result.Detail}. TCP: {tcp.Detail}";
            }
            progress?.Report(Snapshot());
            if (sample < options.Count) await Task.Delay(options.IntervalMs, cancellationToken).ConfigureAwait(false);
        }
        return Snapshot();
    }

    internal static async Task<IPAddress[]> ResolveAsync(string host, CancellationToken token)
    {
        if (IPAddress.TryParse(host, out var address)) return [address];
        var addresses = await Dns.GetHostAddressesAsync(host, token).WaitAsync(TimeSpan.FromSeconds(8), token).ConfigureAwait(false);
        if (addresses.Length == 0) throw new ArgumentException("No IP addresses were returned for this hostname.");
        return addresses.Where(a => a.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6).Take(16).ToArray();
    }

    public static string ServiceName(int port) => port switch
    {
        20 or 21 => "FTP", 22 => "SSH", 23 => "Telnet", 25 or 465 or 587 => "SMTP", 53 => "DNS", 67 or 68 => "DHCP",
        80 or 8000 or 8080 => "HTTP", 110 or 995 => "POP3", 123 => "NTP", 135 => "RPC", 137 or 138 or 139 => "NetBIOS",
        143 or 993 => "IMAP", 161 => "SNMP", 389 or 636 => "LDAP", 443 or 8443 => "HTTPS", 445 => "SMB", 631 => "IPP printing",
        1433 => "SQL Server", 1883 or 8883 => "MQTT", 1900 => "SSDP", 2049 => "NFS", 3306 => "MySQL", 3389 => "Remote Desktop",
        5353 => "mDNS", 5432 => "PostgreSQL", 5900 => "VNC", 6379 => "Redis", 9100 => "Printing", _ => ""
    };
}
