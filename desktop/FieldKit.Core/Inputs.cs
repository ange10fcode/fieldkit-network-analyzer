using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace FieldKit.Core;

public static class Inputs
{
    public static string Host(string host)
    {
        host = host.Trim();
        if (host.StartsWith('[') && host.EndsWith(']')) host = host[1..^1];
        if (host.Length is < 1 or > 253 || host.Any(char.IsWhiteSpace) || host.StartsWith('-') ||
            host.Contains('/') || host.Contains('\\') || host.Contains('@'))
            throw new ArgumentException("Enter an IP address or hostname, without a URL, port or spaces.");
        if (IPAddress.TryParse(host, out _)) return host;
        try { host = new IdnMapping().GetAscii(host.TrimEnd('.')); }
        catch (ArgumentException) { throw new ArgumentException("The hostname is not valid."); }
        if (host.Split('.').Any(part => part.Length is < 1 or > 63 || part.StartsWith('-') || part.EndsWith('-') ||
            part.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-')))
            throw new ArgumentException("The hostname is not valid.");
        return host;
    }

    public static IPAddress? Source(string? address)
    {
        if (string.IsNullOrWhiteSpace(address)) return null;
        if (!IPAddress.TryParse(address.Trim(), out var parsed) || parsed.Equals(IPAddress.Any) || parsed.Equals(IPAddress.IPv6Any))
            throw new ArgumentException("Choose a valid local source address, or leave the source on Automatic.");
        return parsed;
    }

    public static string DnsName(string name)
    {
        name = name.Trim().TrimEnd('.');
        if (name.Length is < 1 or > 253) throw new ArgumentException("Enter a valid DNS name.");
        try { name = new IdnMapping().GetAscii(name); }
        catch (ArgumentException) { throw new ArgumentException("Enter a valid DNS name."); }
        if (name.Split('.').Any(label => label.Length is < 1 or > 63 || label.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_'))))
            throw new ArgumentException("Enter a DNS name containing letters, numbers, hyphens or service underscores.");
        return name;
    }

    public static int[] Ports(string? ports)
    {
        ports = string.IsNullOrWhiteSpace(ports) ? Analyzer.CommonPorts : ports;
        if (ports.Length > 32768) throw new ArgumentException("The port list is too long.");
        var result = new SortedSet<int>();
        foreach (var item in ports.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            var range = item.Split('-', StringSplitOptions.TrimEntries);
            if (range.Length is < 1 or > 2 || !int.TryParse(range[0], NumberStyles.None, CultureInfo.InvariantCulture, out var first) ||
                first is < 1 or > 65535) throw new ArgumentException("Use ports 1–65535, separated by commas, or a range such as 80-90.");
            var last = first;
            if (range.Length == 2 && (!int.TryParse(range[1], NumberStyles.None, CultureInfo.InvariantCulture, out last) || last < first || last > 65535))
                throw new ArgumentException("The port range must be ascending and within 1–65535.");
            if (last - first + 1 > Analyzer.MaxPorts) throw new ArgumentException($"Choose at most {Analyzer.MaxPorts:N0} ports per scan.");
            for (var port = first; port <= last; port++) result.Add(port);
            if (result.Count > Analyzer.MaxPorts) throw new ArgumentException($"Choose at most {Analyzer.MaxPorts:N0} ports per scan.");
        }
        if (result.Count == 0) throw new ArgumentException("Enter at least one port.");
        return result.ToArray();
    }

    public static IReadOnlyList<IPAddress> LanTargets(string target)
    {
        target = target.Trim();
        var parts = target.Split('/');
        if (parts.Length is < 1 or > 2 || !IPAddress.TryParse(parts[0], out var address) || address.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("Enter an IPv4 address or subnet, for example 192.168.1.0/24. IPv6 ranges cannot be enumerated.");
        var prefix = 32;
        if (parts.Length == 2 && (!int.TryParse(parts[1], out prefix) || prefix is < 0 or > 32))
            throw new ArgumentException("The IPv4 prefix must be between 0 and 32.");
        var count = 1UL << (32 - prefix);
        var skip = prefix < 31 ? 1UL : 0;
        var usable = count - skip * 2;
        if (usable > Analyzer.MaxLanHosts) throw new ArgumentException($"This subnet has {usable:N0} hosts. Choose a smaller range, at most {Analyzer.MaxLanHosts:N0} hosts.");
        var number = BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes());
        var mask = prefix == 0 ? 0U : uint.MaxValue << (32 - prefix);
        var start = number & mask;
        var result = new List<IPAddress>((int)usable);
        for (var index = skip; index < count - skip; index++)
        {
            var bytes = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(bytes, start + (uint)index);
            result.Add(new IPAddress(bytes));
        }
        return result;
    }

    public static void Range(int value, int minimum, int maximum, string description)
    {
        if (value < minimum || value > maximum) throw new ArgumentException($"{description} must be between {minimum} and {maximum}.");
    }
}
