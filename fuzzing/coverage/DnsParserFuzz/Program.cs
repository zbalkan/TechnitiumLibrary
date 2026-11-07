using SharpFuzz;
using System.Text.Json;
using System.Diagnostics;
using DnsParserFuzz;
using TechnitiumLibrary.Net.Dns;

if (args.Length == 2 && args[0] == "--target" && SpecializedTargets.Exists(args[1]))
{
    string target = args[1];
    Fuzzer.OutOfProcess.Run(input => SpecializedTargets.Run(target, input));
    return;
}

if (args.Length == 3 && args[0] == "--replay-target" && SpecializedTargets.Exists(args[1]))
{
    using FileStream input = File.OpenRead(args[2]);
    SpecializedTargets.Run(args[1], input);
    return;
}

if (args.Length == 1 && args[0] == "--test-oracle")
{
    TestOracle();
    return;
}

if (args.Length == 4 && args[0] == "--benchmark" &&
    (args[1] == "datagram" || SpecializedTargets.Exists(args[1])) &&
    int.TryParse(args[3], out int iterations) && iterations > 0 && iterations <= 1000000)
{
    Benchmark(args[1], args[2], iterations);
    return;
}

if (args.Length == 2 && args[0] == "--inspect")
{
    Inspect(args[1]);
    return;
}

if (args.Length == 2 && args[0] == "--verify-seeds")
{
    VerifySeeds(args[1]);
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
    await Console.Error.WriteLineAsync("Usage: DnsParserFuzz [--benchmark target file iterations | --inspect file | --target name | --replay-target name file | --replay file | --test-oracle | --verify-seeds directory]");
    Environment.ExitCode = 2;
    return;
}

Fuzzer.OutOfProcess.Run(Parse);

static void Benchmark(string target, string path, int iterations)
{
    byte[] bytes = File.ReadAllBytes(path);
    void Execute()
    {
        using MemoryStream input = new(bytes, writable: false);
        if (target == "datagram")
            Parse(input);
        else
            SpecializedTargets.Run(target, input);
    }

    Execute(); // Warm up JIT and first-use initialization.
    long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
    Stopwatch stopwatch = Stopwatch.StartNew();
    for (int iteration = 0; iteration < iterations; iteration++)
        Execute();
    stopwatch.Stop();
    long allocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;
    Console.WriteLine(JsonSerializer.Serialize(new
    {
        target,
        mode = "in-process-clean-harness",
        iterations,
        elapsed_seconds = stopwatch.Elapsed.TotalSeconds,
        operations_per_second = iterations / Math.Max(stopwatch.Elapsed.TotalSeconds, 0.000001),
        allocated_bytes = allocated
    }));
}

static void Inspect(string path)
{
    using FileStream input = File.OpenRead(path);
    try
    {
        DnsDatagram parsed = DnsDatagram.ReadFrom(input);
        if (parsed.ParsingException is not null)
        {
            Console.WriteLine(JsonSerializer.Serialize(new { accepted = false,
                error = "stored-parse-error" }));
            return;
        }
        Console.WriteLine(JsonSerializer.Serialize(new {
            accepted = true,
            id = parsed.Identifier,
            qr = parsed.IsResponse,
            opcode = (int)parsed.OPCODE,
            rcode = (int)parsed.RCODE,
            questions = parsed.Question.Count,
            answers = parsed.Answer.Count,
            authority = parsed.Authority.Count,
            additional = parsed.Additional.Count
        }));
    }
    catch (EndOfStreamException)
    {
        Console.WriteLine(JsonSerializer.Serialize(new { accepted = false,
            error = "truncated-header" }));
    }
}

static void Parse(Stream input)
{
    // DNS-over-TCP messages have at most 65,535 bytes of DNS payload.
    using MemoryStream buffer = new();
    input.CopyTo(buffer);
    if (buffer.Length > ushort.MaxValue)
        return;

    buffer.Position = 0;
    ParseDatagram(() => DnsDatagram.ReadFrom(buffer), buffer);
}

static void ParseDatagram(Func<DnsDatagram> reader, Stream? wire = null)
{
    try
    {
        DnsDatagram datagram = reader();
        // ReadFrom deliberately catches RR/EDNS parsing errors and returns
        // them in ParsingException. A rejected message is a normal outcome;
        // rethrowing that stored error invents a crash absent in production.
        if (wire is not null && datagram.ParsingException is null)
            SemanticOracle.AssertWireHeaderMatches(datagram, wire);
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
        DnsDatagram parsed = DnsDatagram.ReadFrom(valid);
        if (parsed.ParsingException is not null)
            throw new InvalidOperationException("Valid DNS query failed parser baseline.");
        SemanticOracle.AssertWireHeaderMatches(parsed, valid);
        SemanticOracle.AssertRoundTrip(parsed);

        // Negative controls: prove the semantic oracle detects a corrupted
        // identifier and inconsistent section counts rather than merely
        // accepting every successfully parsed datagram.
        foreach (int index in new[] { 0, 5 })
        {
            byte[] tampered = (byte[])query.Clone();
            tampered[index] ^= 1;
            using MemoryStream changed = new(tampered);
            bool detected = false;
            try
            {
                SemanticOracle.AssertWireHeaderMatches(parsed, changed);
            }
            catch (InvalidOperationException)
            {
                detected = true;
            }
            if (!detected)
                throw new InvalidOperationException($"Semantic oracle missed header mutation at {index}.");
        }
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

static void VerifySeeds(string directory)
{
    // Only the reviewed input shapes have a defined acceptance contract.
    string[] valid = [
        "query-a", "query-aaaa", "query-dnskey", "query-txt",
        "response-a", "response-aaaa", "response-cname",
        "response-txt", "response-mx", "response-soa",
        "query-edns", "response-ede", "nxdomain"
    ];
    string[] rejected = ["short-header", "compression-loop", "rr-truncated"];
    foreach (string name in valid)
        VerifyValidSeed(directory, name);
    foreach (string name in rejected)
        VerifyRejectedSeed(directory, name);
    Console.WriteLine($"Seed oracle passed: {valid.Length} valid, {rejected.Length} rejected.");
}

static void VerifyValidSeed(string directory, string name)
{
    using MemoryStream input = new(File.ReadAllBytes(Path.Combine(directory, name)), writable: false);
    DnsDatagram parsed = DnsDatagram.ReadFrom(input);
    if (parsed.ParsingException is not null)
        throw new InvalidOperationException($"Valid seed rejected: {name}", parsed.ParsingException);
    SemanticOracle.AssertWireHeaderMatches(parsed, input);
    SemanticOracle.AssertRoundTrip(parsed);
}

static void VerifyRejectedSeed(string directory, string name)
{
    using MemoryStream input = new(File.ReadAllBytes(Path.Combine(directory, name)), writable: false);
    bool rejected;
    try
    {
        rejected = DnsDatagram.ReadFrom(input).ParsingException is not null;
    }
    catch (EndOfStreamException)
    {
        rejected = true;
    }
    if (!rejected)
        throw new InvalidOperationException($"Malformed seed accepted: {name}");
}
