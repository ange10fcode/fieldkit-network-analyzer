using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace FieldKit.Core;

public sealed record DnsAnswer(string Name, string Type, uint Ttl, string Value);
public sealed record DnsResponse(string Status, bool Authoritative, List<DnsAnswer> Answers, string Transport);

/// <summary>Bounded DNS wire client with reply ID/question validation and TCP retry on truncation.</summary>
public static class DnsWire
{
    private static readonly Dictionary<string, ushort> Types = new(StringComparer.OrdinalIgnoreCase)
    { ["A"] = 1, ["NS"] = 2, ["CNAME"] = 5, ["SOA"] = 6, ["PTR"] = 12, ["MX"] = 15, ["TXT"] = 16, ["AAAA"] = 28, ["SRV"] = 33 };

    public static async Task<DnsResponse> QueryAsync(string name, string type, IPEndPoint server, int timeoutMs = 3000, CancellationToken token = default)
    {
        try { return await QueryCoreAsync(name, type, server, timeoutMs, token).ConfigureAwait(false); }
        catch (OperationCanceledException) when (!token.IsCancellationRequested) { throw new TimeoutException("The DNS server did not answer within the configured timeout."); }
    }

    private static async Task<DnsResponse> QueryCoreAsync(string name, string type, IPEndPoint server, int timeoutMs, CancellationToken token)
    {
        name = Inputs.DnsName(name);
        if (!Types.TryGetValue(type, out var code)) throw new ArgumentException("Choose A, AAAA, PTR, CNAME, MX, TXT, NS, SOA or SRV.");
        Inputs.Range(timeoutMs, 100, 30000, "DNS timeout in milliseconds");
        var id = (ushort)RandomNumberGenerator.GetInt32(ushort.MaxValue + 1);
        var query = BuildQuery(name, code, id);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        timeout.CancelAfter(timeoutMs);
        using var udp = new UdpClient(server.AddressFamily);
        udp.Connect(server);
        await udp.SendAsync(query, timeout.Token).ConfigureAwait(false);
        var packet = await udp.ReceiveAsync(timeout.Token).ConfigureAwait(false);
        ValidateQuestion(packet.Buffer, name, code, id);
        if ((packet.Buffer[2] & 2) == 0) return Parse(packet.Buffer, name, code, id, "UDP");
        using var tcp = new TcpClient(server.AddressFamily);
        await tcp.ConnectAsync(server.Address, server.Port, timeout.Token).ConfigureAwait(false);
        var stream = tcp.GetStream();
        var frame = new byte[query.Length + 2];
        BinaryPrimitives.WriteUInt16BigEndian(frame, (ushort)query.Length);
        query.CopyTo(frame, 2);
        await stream.WriteAsync(frame, timeout.Token).ConfigureAwait(false);
        var length = new byte[2];
        await stream.ReadExactlyAsync(length, timeout.Token).ConfigureAwait(false);
        var data = new byte[BinaryPrimitives.ReadUInt16BigEndian(length)];
        if (data.Length < 12) throw new InvalidDataException("The DNS TCP reply was incomplete.");
        await stream.ReadExactlyAsync(data, timeout.Token).ConfigureAwait(false);
        return Parse(data, name, code, id, "TCP after truncated UDP");
    }

    private static byte[] BuildQuery(string name, ushort type, ushort id)
    {
        using var memory = new MemoryStream();
        var header = new byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(header, id);
        header[2] = 1; header[5] = 1;
        memory.Write(header);
        foreach (var label in name.Split('.'))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            if (bytes.Length is < 1 or > 63) throw new ArgumentException("A DNS label must contain 1–63 bytes.");
            memory.WriteByte((byte)bytes.Length); memory.Write(bytes);
        }
        memory.WriteByte(0); memory.WriteByte((byte)(type >> 8)); memory.WriteByte((byte)type);
        memory.WriteByte(0); memory.WriteByte(1);
        return memory.ToArray();
    }

    private static void ValidateQuestion(byte[] data, string name, ushort type, ushort id)
    {
        if (data.Length < 12 || BinaryPrimitives.ReadUInt16BigEndian(data) != id || (data[2] & 0x80) == 0 ||
            BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(4)) != 1)
            throw new InvalidDataException("The DNS server returned an unrelated or malformed reply.");
        var position = 12;
        var question = ReadName(data, ref position);
        Require(data, position, 4);
        if (!question.Equals(name, StringComparison.OrdinalIgnoreCase) || Read16(data, position) != type || Read16(data, position + 2) != 1)
            throw new InvalidDataException("The DNS reply question did not match the query.");
    }

    internal static DnsResponse Parse(byte[] data, string name, ushort type, ushort id, string transport)
    {
        ValidateQuestion(data, name, type, id);
        var position = 12;
        _ = ReadName(data, ref position); position += 4;
        var count = Read16(data, 6);
        if (count > 2048) throw new InvalidDataException("Too many DNS answers.");
        var answers = new List<DnsAnswer>();
        for (var index = 0; index < count; index++)
        {
            var owner = ReadName(data, ref position);
            Require(data, position, 10);
            var recordType = Read16(data, position);
            var recordClass = Read16(data, position + 2);
            var ttl = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(position + 4));
            var size = Read16(data, position + 8);
            position += 10;
            Require(data, position, size);
            var end = position + size;
            string value;
            var cursor = position;
            if (recordType == 1 && size == 4 || recordType == 28 && size == 16) value = new IPAddress(data.AsSpan(position, size)).ToString();
            else if (recordType is 2 or 5 or 12) value = ReadName(data, ref cursor);
            else if (recordType == 15 && size >= 3) { value = $"{Read16(data, cursor)} "; cursor += 2; value += ReadName(data, ref cursor); }
            else if (recordType == 33 && size >= 7) { value = $"priority {Read16(data, cursor)}, weight {Read16(data, cursor + 2)}, port {Read16(data, cursor + 4)}, target "; cursor += 6; value += ReadName(data, ref cursor); }
            else if (recordType == 16)
            {
                var text = new List<string>();
                while (cursor < end)
                {
                    var length = data[cursor++];
                    if (cursor + length > end) throw new InvalidDataException("Malformed TXT record.");
                    text.Add(Encoding.UTF8.GetString(data, cursor, length)); cursor += length;
                }
                value = string.Join(" ", text);
            }
            else if (recordType == 6)
            {
                var primary = ReadName(data, ref cursor); var contact = ReadName(data, ref cursor);
                Require(data, cursor, 20);
                value = $"primary {primary}, contact {contact}, serial {BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(cursor))}";
                cursor += 20;
            }
            else value = Convert.ToHexString(data.AsSpan(position, size));
            if (cursor > end) throw new InvalidDataException("A DNS record exceeded its declared length.");
            if (recordClass == 1) answers.Add(new(owner, Types.FirstOrDefault(p => p.Value == recordType).Key ?? $"TYPE{recordType}", ttl, value));
            position = end;
        }
        var rcode = data[3] & 15;
        var status = rcode switch { 0 => "Success", 1 => "Format error", 2 => "Server failure", 3 => "Name does not exist", 4 => "Not implemented", 5 => "Refused", _ => $"DNS error {rcode}" };
        return new(status, (data[2] & 4) != 0, answers, transport);
    }

    private static string ReadName(byte[] data, ref int position)
    {
        var labels = new List<string>(); var cursor = position; var jumped = false;
        var seen = new HashSet<int>(); var total = 0;
        while (true)
        {
            Require(data, cursor, 1);
            if (!seen.Add(cursor) || seen.Count > 128) throw new InvalidDataException("DNS compression loop.");
            var length = data[cursor++];
            if (length == 0) { if (!jumped) position = cursor; break; }
            if ((length & 0xC0) == 0xC0)
            {
                Require(data, cursor, 1);
                var pointer = ((length & 63) << 8) | data[cursor++];
                if (!jumped) position = cursor;
                jumped = true; cursor = pointer; continue;
            }
            if ((length & 0xC0) != 0) throw new InvalidDataException("Malformed DNS label.");
            Require(data, cursor, length);
            total += length + 1;
            if (total > 254) throw new InvalidDataException("DNS name too long.");
            labels.Add(Encoding.ASCII.GetString(data, cursor, length)); cursor += length;
            if (!jumped) position = cursor;
        }
        return string.Join('.', labels);
    }

    private static ushort Read16(byte[] data, int offset) { Require(data, offset, 2); return BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(offset)); }
    private static void Require(byte[] data, int position, int count)
    { if (position < 0 || count < 0 || position > data.Length - count) throw new InvalidDataException("The DNS packet was incomplete."); }
}

public static partial class Analyzer
{
    public static async Task<Report> DnsAsync(DnsOptions options, CancellationToken cancellationToken = default)
    {
        Inputs.Range(options.TimeoutMs, 100, 30000, "DNS timeout in milliseconds");
        var host = options.RecordType.Equals("PTR", StringComparison.OrdinalIgnoreCase) ? Inputs.Host(options.Host) : Inputs.DnsName(options.Host);
        var type = options.RecordType.ToUpperInvariant();
        if (type == "PTR" && IPAddress.TryParse(host, out var reverse)) host = ReverseName(reverse);
        if (string.IsNullOrWhiteSpace(options.Server))
        {
            if (type is not ("A" or "AAAA" or "PTR")) throw new ArgumentException("Select a DNS server for MX, TXT, NS, SOA, CNAME or SRV records. System lookup supports A, AAAA and PTR.");
            var rows = new List<List<string>>();
            if (type == "PTR")
            {
                if (!IPAddress.TryParse(options.Host, out var address)) throw new ArgumentException("System PTR lookup needs a literal IP address.");
                var entry = await Dns.GetHostEntryAsync(address).WaitAsync(TimeSpan.FromMilliseconds(options.TimeoutMs), cancellationToken).ConfigureAwait(false);
                if (!IPAddress.TryParse(entry.HostName, out _)) rows.Add([options.Host, "PTR", entry.HostName, "OS resolver; TTL unavailable"]);
            }
            else
            {
                var addresses = await Dns.GetHostAddressesAsync(host, cancellationToken).WaitAsync(TimeSpan.FromMilliseconds(options.TimeoutMs), cancellationToken).ConfigureAwait(false);
                foreach (var address in addresses.Where(a => type == "A" ? a.AddressFamily == AddressFamily.InterNetwork : a.AddressFamily == AddressFamily.InterNetworkV6).Distinct())
                    rows.Add([host, type, address.ToString(), "OS resolver; TTL unavailable"]);
            }
            return Report.Create("dns", $"DNS · {options.Host}", ["Name", "Record", "Value", "Source"], rows,
                "System resolver: OS search, hosts-file and cache policies apply. An empty answer means no matching records were returned.");
        }
        if (!IPAddress.TryParse(options.Server.Trim(), out var server)) throw new ArgumentException("The custom DNS server must be an IP address.");
        Inputs.Range(options.ServerPort, 1, 65535, "DNS server port");
        var response = await DnsWire.QueryAsync(host, type, new(server, options.ServerPort), options.TimeoutMs, cancellationToken).ConfigureAwait(false);
        return Report.Create("dns", $"DNS · {options.Host}", ["Name", "Record", "Value", "TTL"],
            response.Answers.Select(a => new[] { a.Name, a.Type, a.Value, $"{a.Ttl} s" }),
            $"Server {server}:{options.ServerPort} · {response.Transport} · {response.Status} · authoritative: {(response.Authoritative ? "yes" : "no")}",
            "Answers are returned as provided by the server. This query does not perform DNSSEC validation.");
    }

    private static string ReverseName(IPAddress address) => address.AddressFamily == AddressFamily.InterNetwork
        ? string.Join('.', address.GetAddressBytes().Reverse()) + ".in-addr.arpa"
        : string.Join('.', Convert.ToHexString(address.GetAddressBytes()).ToLowerInvariant().Reverse()) + ".ip6.arpa";
}
