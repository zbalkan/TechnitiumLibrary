using SharpFuzz;
using TechnitiumLibrary.Net.Dns;

if (args.Length == 1 && args[0] == "--test-oracle")
{
    TestOracle();
    return;
}

if (args.Length == 2 && args[0] == "--replay")
{
    using FileStream input = File.OpenRead(args[1]);
    Parse(input);
    return;
}

if (args.Length != 0)
{
    await Console.Error.WriteLineAsync("Usage: DnsParserFuzz [--replay input-file | --test-oracle]");
    Environment.ExitCode = 2;
    return;
}

Fuzzer.OutOfProcess.Run(Parse);

static void Parse(Stream input)
{
    // DNS-over-TCP messages have at most 65,535 bytes of DNS payload.
    using MemoryStream buffer = new();
    input.CopyTo(buffer);
    if (buffer.Length > ushort.MaxValue)
        return;

    buffer.Position = 0;
    ParseDatagram(() => DnsDatagram.ReadFrom(buffer));
}

static void ParseDatagram(Func<DnsDatagram> reader)
{
    try
    {
        DnsDatagram datagram = reader();
        // ReadFrom deliberately catches RR/EDNS parsing errors and returns
        // them in ParsingException. A rejected message is a normal outcome;
        // rethrowing that stored error invents a crash absent in production.
        _ = datagram.ParsingException;
    }
    catch (EndOfStreamException)
    {
        // Truncated DNS headers fail before ReadFrom's RR parsing catch block.
    }
}

static void TestOracle()
{
    // A complete, valid DNS query must parse without an error.
    byte[] query =
    [
        0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
        1, (byte)'a', 0, 0, 1, 0, 1
    ];
    using (MemoryStream valid = new(query))
    {
        if (DnsDatagram.ReadFrom(valid).ParsingException is not null)
            throw new InvalidOperationException("Valid DNS query failed parser baseline.");
    }

    // An RSA DNSKEY with no public-key bytes triggers an internal decoding
    // exception in the unmodified library. ReadFrom stores that exception,
    // instead of throwing it. The harness must preserve that contract.
    byte[] malformed =
    [
        0x12, 0x34, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0,
        0, 0, 48, 0, 1, 0, 0, 0, 60, 0, 4,
        1, 0, 3, 8
    ];
    using (MemoryStream rejected = new(malformed))
    {
        DnsDatagram datagram = DnsDatagram.ReadFrom(rejected);
        if (datagram.ParsingException is null)
            throw new InvalidOperationException("Malformed RSA DNSKEY was not rejected.");
        rejected.Position = 0;
        Parse(rejected);
    }

    // Truncated wire headers are expected to throw EndOfStreamException.
    using (MemoryStream truncated = new([0x12, 0x34, 0x01]))
        Parse(truncated);

    // A genuine escaping parser defect must not be swallowed by the oracle.
    try
    {
        ParseDatagram(() => throw new InvalidOperationException("synthetic unhandled failure"));
    }
    catch (InvalidOperationException)
    {
        Console.WriteLine("Parser oracle regression tests passed.");
        return;
    }

    throw new InvalidOperationException("Parser oracle hid an escaping exception.");
}
