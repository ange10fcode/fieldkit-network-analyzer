using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace FieldKit.Core;

public static partial class Analyzer
{
    public static Task<IReadOnlyList<NetworkProfile>> GetNetworksAsync(CancellationToken cancellationToken = default) =>
        Task.Run(GetNetworks, cancellationToken);

    public static IReadOnlyList<NetworkProfile> GetNetworks()
    {
        var result = new List<NetworkProfile>();
        foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
        {
            try
            {
                var ip = adapter.GetIPProperties();
                var addresses = ip.UnicastAddresses
                    .Where(a => a.Address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                    .Select(a => new NetworkAddress(a.Address.ToString(), a.PrefixLength,
                        a.Address.AddressFamily == AddressFamily.InterNetwork ? "IPv4" : "IPv6"))
                    .OrderBy(a => a.Family).ThenBy(a => a.Address, StringComparer.Ordinal).ToList();
                var gateways = ip.GatewayAddresses.Select(a => a.Address)
                    .Where(a => !a.Equals(IPAddress.Any) && !a.Equals(IPAddress.IPv6Any))
                    .Select(a => a.ToString()).Distinct().ToList();
                var mac = adapter.GetPhysicalAddress().ToString();
                if (mac.Length > 0) mac = string.Join(":", Enumerable.Range(0, mac.Length / 2).Select(i => mac.Substring(i * 2, 2)));
                long speed = 0;
                try { speed = adapter.Speed; } catch (NetworkInformationException) { }
                result.Add(new(adapter.Id, adapter.Name, adapter.Description, Classify(adapter),
                    adapter.OperationalStatus.ToString(), mac, addresses, gateways,
                    ip.DnsAddresses.Select(a => a.ToString()).Distinct().ToList(), gateways.Count > 0,
                    adapter.SupportsMulticast, speed));
            }
            catch (NetworkInformationException)
            {
                result.Add(new(adapter.Id, adapter.Name, adapter.Description, Classify(adapter),
                    adapter.OperationalStatus.ToString(), "", [], [], [], false, false, 0));
            }
        }
        return result.OrderByDescending(n => n.Status == "Up").ThenBy(n => n.Kind == "Loopback")
            .ThenBy(n => n.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static string Classify(NetworkInterface adapter)
    {
        var label = (adapter.Name + " " + adapter.Description).ToLowerInvariant();
        if (adapter.NetworkInterfaceType is NetworkInterfaceType.Tunnel or NetworkInterfaceType.Ppp ||
            new[] { "tailscale", "wireguard", "zerotier", "openvpn", "vpn" }.Any(label.Contains) ||
            adapter.Name.StartsWith("tun", StringComparison.OrdinalIgnoreCase) || adapter.Name.StartsWith("tap", StringComparison.OrdinalIgnoreCase)) return "VPN / tunnel";
        return adapter.NetworkInterfaceType switch
        {
            NetworkInterfaceType.Wireless80211 => "Wi-Fi",
            NetworkInterfaceType.Ethernet or NetworkInterfaceType.GigabitEthernet or NetworkInterfaceType.FastEthernetFx or NetworkInterfaceType.FastEthernetT => "Ethernet",
            NetworkInterfaceType.Loopback => "Loopback",
            NetworkInterfaceType.Wman or NetworkInterfaceType.Wwanpp or NetworkInterfaceType.Wwanpp2 => "Cellular",
            _ => adapter.NetworkInterfaceType.ToString()
        };
    }

    public static Report NetworkReport(IEnumerable<NetworkProfile> networks) => Report.Create("networks", "Connected networks",
        ["Interface", "Type", "Status", "Addresses", "Gateways", "DNS servers", "Hardware address"],
        networks.Select(n => new[] { n.Name, n.Kind, n.Status,
            string.Join("\n", n.Addresses.Select(a => a.Cidr)), string.Join("\n", n.Gateways),
            string.Join("\n", n.DnsServers), n.Mac }),
        "Each adapter is listed separately, including VPNs. Gateway presence does not prove that it is the default route.",
        "Diagnostics follow the operating system route. A selected TCP source address binds probes to that local address; VPN policy can still reject them.");
}
