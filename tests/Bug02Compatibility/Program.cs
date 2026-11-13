using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

int failures = 0;
int tests = 0;
Test("Standard name validates", () => Require(DnsClient.IsDomainNameValid("www.example.com"), "Ordinary name rejected"));
Test("Escaped literal-period label validates", () => Require(DnsClient.IsDomainNameValid(@"a\.b.example"), "Wire-valid escaped name rejected"));
Test("RRSIG label count preserves literal periods", () => Require(DnsRRSIGRecordData.GetLabelCount(@"a\.b.example") == 2, "Should be two labels"));
Test("NSEC canonical ordering respects literal periods", () => Require(DnsNSECRecordData.CanonicalComparison(@"a\.b.example", "b.example") < 0, "Expected a.b < b within corresponding rightmost labels"));
Test("DNS question uncompressed size accounts for escaping", () =>
{
    byte[] q = Convert.FromHexString("03612e62076578616d706c650000010001");
    using MemoryStream stream = new(q, writable: false);
    var parsed = new DnsQuestionRecord(stream);
    Require(parsed.Name == @"a\.b.example", $"Unexpected QNAME {parsed.Name}");
    Require(parsed.UncompressedLength == q.Length,
        $"Computed {parsed.UncompressedLength}, wire requires {q.Length}");
});
Test("NSEC canonical comparison ordinary names preserved", () =>
    Require(DnsNSECRecordData.CanonicalComparison("a.example", "b.example") < 0,
        "Ordinary comparison changed"));
Test("NSEC3 next closer name respects escaped separators", () =>
    Require(DnsNSEC3RecordData.GetNextCloserName(@"x.a\.b.example", "example") == @"a\.b.example",
        "NSEC3 next closer name split a single DNS label"));
Test("Public DNS question constructor accepts a decoded escaped name", () =>
{
    DnsQuestionRecord question = new(@"a\.b.example", DnsResourceRecordType.A, DnsClass.IN);
    using MemoryStream output = new();
    question.WriteTo(output, []);
    Require(Convert.ToHexString(output.ToArray()) == "03612E62076578616D706C650000010001",
        "Question constructor changed escaped DNS label bytes");
});
Test("Invalid ordinary names remain rejected", () =>
{
    foreach (string name in new[] { ".example", "example.", "a..b", @"a\q.example", "bad!name.example" })
        Require(!DnsClient.IsDomainNameValid(name), $"Unexpectedly accepted '{name}'");
});
Test("Encoded-domain length matches wire length", () =>
    Require(DnsDatagram.GetSerializeDomainNameLength(@"a\.b.example") == 13,
        "Wrong encoded name size"));
Test("Ordinary names decode and serialize without changes", () =>
    CheckRoundTrip(Convert.FromHexString("03777777076578616d706c6503636f6d00")));
Test("Literal period and backslash decode and serialize without changes", () =>
    CheckRoundTrip(Convert.FromHexString("05612e625c6300")));
Test("Random valid wire-name round trips", () =>
{
    Random random = new(20261114);
    for (int i = 0; i < 512; i++)
    {
        using MemoryStream encoded = new();
        int remaining = 254;
        int n = random.Next(1, 5);
        for (int labelIndex = 0; labelIndex < n; labelIndex++)
        {
            int max = Math.Min(63, remaining - (n - labelIndex));
            int count = random.Next(1, max + 1);
            encoded.WriteByte((byte)count);
            remaining -= count + 1;
            byte[] octets = new byte[count];
            random.NextBytes(octets);
            encoded.Write(octets);
        }
        encoded.WriteByte(0);
        CheckRoundTrip(encoded.ToArray());
    }
});
Console.WriteLine($"BUG-02 compatibility: {tests - failures}/{tests} passed");
return failures == 0 ? 0 : 1;

void Test(string name, Action action)
{
    tests++;
    try
    {
        action();
        Console.WriteLine($"PASS {name}");
    }
    catch (Exception e)
    {
        failures++;
        Console.WriteLine($"FAIL {name}: {e.GetType().Name} {e.Message}");
    }
}

static void Require(bool condition, string message)
{
    if (!condition)
        throw new InvalidOperationException(message);
}

static void CheckRoundTrip(byte[] original)
{
    using MemoryStream input = new(original, writable: false);
    string name = DnsDatagram.DeserializeDomainName(input);
    using MemoryStream output = new();
    DnsDatagram.SerializeDomainName(name, output);
    if (!output.ToArray().AsSpan().SequenceEqual(original))
        throw new InvalidOperationException($"Wire bytes changed: {Convert.ToHexString(original)} => {Convert.ToHexString(output.ToArray())}");
}
