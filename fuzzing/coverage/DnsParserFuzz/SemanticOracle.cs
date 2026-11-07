using System.Buffers.Binary;
using TechnitiumLibrary.Net.Dns;

// Only assert invariants guaranteed by the *successful* parser contract.
// Do not call exceptions recorded in ParsingException process crashes.
internal static class SemanticOracle
{
    internal static void AssertWireHeaderMatches(DnsDatagram parsed, Stream wire)
    {
        if (parsed.ParsingException is not null)
            throw new InvalidOperationException("Semantic validation requires a successfully parsed datagram.");
        long original = wire.Position;
        try
        {
            wire.Position = 0;
            Span<byte> header = stackalloc byte[12];
            wire.ReadExactly(header);
            ushort id = BinaryPrimitives.ReadUInt16BigEndian(header);
            ushort flags = BinaryPrimitives.ReadUInt16BigEndian(header[2..]);
            if (parsed.Identifier != id || parsed.IsResponse != ((flags & 0x8000) != 0))
                throw new InvalidOperationException("Parser changed the DNS identifier or response bit.");
            if (parsed.Question.Count != BinaryPrimitives.ReadUInt16BigEndian(header[4..]) ||
                parsed.Answer.Count != BinaryPrimitives.ReadUInt16BigEndian(header[6..]) ||
                parsed.Authority.Count != BinaryPrimitives.ReadUInt16BigEndian(header[8..]) ||
                parsed.Additional.Count != BinaryPrimitives.ReadUInt16BigEndian(header[10..]))
                throw new InvalidOperationException("Successful parsing disagrees with DNS section counts.");
        }
        finally
        {
            wire.Position = original;
        }
    }

    internal static void AssertRoundTrip(DnsDatagram original)
    {
        using MemoryStream encoded = new();
        original.WriteTo(encoded);
        encoded.Position = 0;
        DnsDatagram reparsed = DnsDatagram.ReadFrom(encoded);
        if (reparsed.ParsingException is not null)
            throw new InvalidOperationException("Serialized valid datagram cannot be parsed.", reparsed.ParsingException);
        AssertWireHeaderMatches(reparsed, encoded);
        if (original.Identifier != reparsed.Identifier ||
            original.IsResponse != reparsed.IsResponse ||
            original.OPCODE != reparsed.OPCODE ||
            original.RCODE != reparsed.RCODE ||
            original.Question.Count != reparsed.Question.Count ||
            original.Answer.Count != reparsed.Answer.Count ||
            original.Authority.Count != reparsed.Authority.Count ||
            original.Additional.Count != reparsed.Additional.Count)
            throw new InvalidOperationException("DNS message semantics changed during round-trip.");
    }
}
