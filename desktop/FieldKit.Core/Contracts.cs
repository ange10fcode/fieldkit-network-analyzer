namespace FieldKit.Core;

/// <summary>Observed output, including its time and provenance. Empty cells mean unavailable, never an inferred capability.</summary>
public sealed record Report(string Tool, string Title, DateTimeOffset CreatedAt, List<string> Columns,
    List<List<string>> Rows, List<string> Summary)
{
    public static Report Create(string tool, string title, IEnumerable<string> columns,
        IEnumerable<IEnumerable<string>> rows, params string[] summary) =>
        new(tool, title, DateTimeOffset.UtcNow, columns.ToList(), rows.Select(r => r.ToList()).ToList(), summary.ToList());
}

public sealed record NetworkAddress(string Address, int PrefixLength, string Family)
{
    public string Cidr => $"{Address}/{PrefixLength}";
}

public sealed record NetworkProfile(string Id, string Name, string Description, string Kind, string Status,
    string Mac, List<NetworkAddress> Addresses, List<string> Gateways, List<string> DnsServers,
    bool HasGateway, bool SupportsMulticast, long SpeedBitsPerSecond)
{
    public override string ToString() => $"{Name} · {Kind} · {string.Join(", ", Addresses.Select(a => a.Cidr))}";
}

public sealed record LanScanOptions(string Target, string? Ports = null, int TimeoutMs = 500,
    int Concurrency = 32, string? SourceAddress = null, bool ResolveNames = true);
public sealed record PortScanOptions(string Host, string? Ports = null, int TimeoutMs = 700,
    int Concurrency = 32, string? SourceAddress = null);
public sealed record PingOptions(string Host, int Count = 4, int TimeoutMs = 1500,
    int IntervalMs = 500, int? TcpFallbackPort = null);
public sealed record DnsOptions(string Host, string RecordType = "A", string? Server = null,
    int TimeoutMs = 3000, int ServerPort = 53);
public sealed record TraceOptions(string Host, int MaxHops = 20, int TimeoutMs = 1000);
public sealed record WakeOptions(string MacAddress, string BroadcastAddress = "255.255.255.255", int Port = 9);
public sealed record Favorite(string Name, string Tool, string Target, string? Extra = null);

/// <summary>All network activity uses the OS route unless an explicit TCP source address is requested.</summary>
public static partial class Analyzer
{
    public const string CommonPorts = "21,22,23,25,53,80,110,139,143,443,445,465,587,631,993,995,3389,8080";
    public const int MaxLanHosts = 4096;
    public const int MaxPorts = 4096;
}
