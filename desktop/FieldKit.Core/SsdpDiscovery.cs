using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace FieldKit.Core;

internal sealed record DiscoveredName(string Address, string Name, string Evidence);

internal static class SsdpDiscovery
{
    public static async Task<IReadOnlyList<DiscoveredName>> FindAsync(IReadOnlyList<IPAddress> targets, CancellationToken token,
        IPAddress? source = null, IPEndPoint? searchDestination = null, int scanMs = 1800)
    {
        var allowed = targets.Select(a => a.ToString()).ToHashSet(StringComparer.Ordinal);
        var descriptions = new Dictionary<string, Uri>(StringComparer.Ordinal);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(scanMs);
        try
        {
            using var udp = new UdpClient(new IPEndPoint(source ?? IPAddress.Any, 0));
            udp.MulticastLoopback = false;
            if (source is not null) udp.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, source.GetAddressBytes());
            var request = Encoding.ASCII.GetBytes("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n");
            await udp.SendAsync(request, searchDestination ?? new IPEndPoint(IPAddress.Parse("239.255.255.250"), 1900), deadline.Token).ConfigureAwait(false);
            while (descriptions.Count < 16)
            {
                var received = await udp.ReceiveAsync(deadline.Token).ConfigureAwait(false);
                if (received.Buffer.Length > 32768 || !allowed.Contains(received.RemoteEndPoint.Address.ToString())) continue;
                var text = Encoding.UTF8.GetString(received.Buffer);
                if (!text.StartsWith("HTTP/1.1 200", StringComparison.OrdinalIgnoreCase) && !text.StartsWith("HTTP/1.0 200", StringComparison.OrdinalIgnoreCase)) continue;
                foreach (var line in text.Split('\n'))
                {
                    var separator = line.IndexOf(':');
                    if (separator > 0 && line[..separator].Trim().Equals("location", StringComparison.OrdinalIgnoreCase) &&
                        Uri.TryCreate(line[(separator + 1)..].Trim(), UriKind.Absolute, out var uri) && ValidLocation(uri, received.RemoteEndPoint.Address))
                        descriptions.TryAdd(received.RemoteEndPoint.Address.ToString(), uri);
                }
            }
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested) { }
        catch (SocketException) { /* Multicast can be blocked by a VPN, firewall or an interface policy. */ }
        token.ThrowIfCancellationRequested();
        using var fetchDeadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        fetchDeadline.CancelAfter(TimeSpan.FromSeconds(4));
        var results = new System.Collections.Concurrent.ConcurrentBag<DiscoveredName>();
        try
        {
            await Parallel.ForEachAsync(descriptions, new ParallelOptions { MaxDegreeOfParallelism = 4, CancellationToken = fetchDeadline.Token }, async (item, cancellation) =>
            {
                try
                {
                    var name = await ReadDescriptionAsync(item.Value, IPAddress.Parse(item.Key), source, cancellation).ConfigureAwait(false);
                    if (name is not null) results.Add(new(item.Key, name, $"Name: UPnP friendlyName from {item.Value}. Service advertisement; ports not inferred open."));
                }
                catch (Exception error) when (error is HttpRequestException or IOException or XmlException or OperationCanceledException or SocketException) { }
            }).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested) { }
        return results.OrderBy(r => r.Address, StringComparer.Ordinal).ToList();
    }

    internal static bool ValidLocation(Uri uri, IPAddress sender) => uri.Scheme == "http" && uri.UserInfo.Length == 0 &&
        IPAddress.TryParse(uri.Host, out var host) && host.Equals(sender) && PrivateAddress(sender);

    private static bool PrivateAddress(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork) return false;
        var bytes = address.GetAddressBytes();
        return bytes[0] == 10 || bytes[0] == 127 || bytes[0] == 172 && bytes[1] is >= 16 and <= 31 ||
            bytes[0] == 192 && bytes[1] == 168 || bytes[0] == 169 && bytes[1] == 254 || bytes[0] == 100 && bytes[1] is >= 64 and <= 127;
    }

    internal static async Task<string?> ReadDescriptionAsync(Uri uri, IPAddress sender, IPAddress? source, CancellationToken token)
    {
        if (!ValidLocation(uri, sender)) return null;
        using var handler = new SocketsHttpHandler { AllowAutoRedirect = false, UseProxy = false, ConnectTimeout = TimeSpan.FromMilliseconds(900) };
        if (source is not null)
        {
            handler.ConnectCallback = async (context, cancellation) =>
            {
                var socket = new Socket(source.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    socket.Bind(new IPEndPoint(source, 0));
                    // The description URL was validated to the same literal IP that sent the SSDP reply.
                    await socket.ConnectAsync(new IPEndPoint(sender, context.DnsEndPoint.Port), cancellation).ConfigureAwait(false);
                    return new NetworkStream(socket, true);
                }
                catch { socket.Dispose(); throw; }
            };
        }
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(1800) };
        using var response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, token).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode) return null;
        var bytes = await Analyzer.ReadBoundedAsync(response.Content, 262144, token).ConfigureAwait(false);
        using var stream = new MemoryStream(bytes);
        using var reader = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null, MaxCharactersInDocument = 262144, MaxCharactersFromEntities = 0 });
        var document = XDocument.Load(reader);
        var name = document.Descendants().FirstOrDefault(e => e.Name.LocalName == "device")?.Elements().FirstOrDefault(e => e.Name.LocalName == "friendlyName")?.Value.Trim();
        if (string.IsNullOrWhiteSpace(name)) return null;
        return new string(name.Where(c => !char.IsControl(c)).Take(256).ToArray());
    }
}
