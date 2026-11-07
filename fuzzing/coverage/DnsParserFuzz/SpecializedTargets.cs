using System.Buffers.Binary;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsParserFuzz;

// The wrappers preserve the real DNS wire parsing path. A rejected RR or EDNS
// option stays in DnsDatagram.ParsingException, as in production.
internal static class SpecializedTargets
{
    private static readonly ushort[] RdataTypes =
    [
        1, 2, 5, 6, 12, 15, 16, 28, 33, 35
    ];

    private static readonly ushort[] DnssecTypes = [43, 46, 47, 48, 50, 51];

    internal static void Run(string target, Stream input)
    {
        byte[]? data = InputBudget.ReadCapped(input);
        if (data is null)
            return;
        switch (target)
        {
            case "name":
                ParseName(data);
                break;
            case "rdata":
                ParseRecord(data, RdataTypes);
                break;
            case "dnssec":
                ParseRecord(data, DnssecTypes);
                break;
            case "edns":
                ParseEdns(data);
                break;
            case "serialization":
                ParseSerialization(data);
                break;
            default:
                throw new ArgumentException($"Unsupported fuzzing target: {target}");
        }
    }

    internal static bool Exists(string target) =>
        target is "name" or "rdata" or "dnssec" or "edns" or "serialization";

    private static void ParseName(byte[] payload)
    {
        using MemoryStream input = new(payload, writable: false);
        try
        {
            string name = DnsDatagram.DeserializeDomainName(input);
            if (name.Length > 255)
                throw new InvalidOperationException("Name parser returned a name longer than 255 characters.");
        }
        catch (DnsClientException)
        {
            // Malformed labels and cyclic compression are rejected.
        }
        catch (EndOfStreamException)
        {
            // Truncated name is rejected.
        }
    }

    private static void ParseRecord(byte[] bytes, ushort[] types)
    {
        if (bytes.Length == 0)
            return;
        ushort type = types[bytes[0] % types.Length];
        ParseWrappedRecord(type, bytes.AsSpan(1), opt: false, roundTrip: false);
    }

    private static void ParseEdns(byte[] bytes) =>
        ParseWrappedRecord(41, bytes, opt: true, roundTrip: false);

    private static void ParseSerialization(byte[] bytes)
    {
        using MemoryStream input = new(bytes, writable: false);
        try
        {
            DnsDatagram parsed = DnsDatagram.ReadFrom(input);
            if (parsed.ParsingException is null)
            {
                SemanticOracle.AssertWireHeaderMatches(parsed, input);
                SemanticOracle.AssertRoundTrip(parsed);
            }
        }
        catch (EndOfStreamException)
        {
            // Incomplete wire header.
        }
    }

    private static void ParseWrappedRecord(ushort type, ReadOnlySpan<byte> payload, bool opt, bool roundTrip)
    {
        if (payload.Length > ushort.MaxValue - 23)
            return;
        using MemoryStream wire = new();
        // Response header with one answer (RR) or one additional (OPT).
        Span<byte> header = stackalloc byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(header, 0x1234);
        BinaryPrimitives.WriteUInt16BigEndian(header[2..], 0x8180);
        BinaryPrimitives.WriteUInt16BigEndian(header[(opt ? 10 : 6)..], 1);
        wire.Write(header);
        wire.WriteByte(0); // root record owner
        Span<byte> rrHeader = stackalloc byte[10];
        BinaryPrimitives.WriteUInt16BigEndian(rrHeader, type);
        BinaryPrimitives.WriteUInt16BigEndian(rrHeader[2..], opt ? (ushort)1232 : (ushort)1);
        BinaryPrimitives.WriteUInt32BigEndian(rrHeader[4..], 60);
        BinaryPrimitives.WriteUInt16BigEndian(rrHeader[8..], checked((ushort)payload.Length));
        wire.Write(rrHeader);
        wire.Write(payload);
        wire.Position = 0;
        DnsDatagram parsed = DnsDatagram.ReadFrom(wire);
        if (parsed.ParsingException is null)
        {
            SemanticOracle.AssertWireHeaderMatches(parsed, wire);
            if (roundTrip)
                SemanticOracle.AssertRoundTrip(parsed);
        }
    }
}
