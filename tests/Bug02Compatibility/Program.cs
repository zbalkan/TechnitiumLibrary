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
Test("QNAME minimization preserves escaped label boundaries", () =>
{
    var q = new DnsQuestionRecord(@"a\.b.com", DnsResourceRecordType.A, DnsClass.IN);
    var binding = System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance;
    var zoneCut = typeof(DnsQuestionRecord).GetProperty("ZoneCut", binding);
    var minimized = typeof(DnsQuestionRecord).GetProperty("MinimizedName", binding);
    if (zoneCut is null || minimized is null)
        throw new InvalidOperationException("QNAME minimization accessors missing");
    zoneCut.SetValue(q, "com");
    Require((string?)minimized.GetValue(q) == @"a\.b.com", "QNAME minimization split escaped label");
});
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
Test("Zone-file relative naming does not split an escaped label", () =>
{
    var rr = new DnsResourceRecord(@"a\.example", DnsResourceRecordType.A,
        DnsClass.IN, 60, new DnsARecordData(System.Net.IPAddress.Parse("192.0.2.1")));
    string entry = rr.ToZoneFileEntry("example");
    Require(entry.StartsWith(@"a\.example.", StringComparison.Ordinal),
        $"Zone file owner incorrectly relativized: {entry}");
});
Test("Zone-file parser treats escaped trailing period as label data", () =>
{
    using StringReader reader = new(@"a\. 60 IN A 192.0.2.1");
    var records = ZoneFile.ReadZoneFileFromAsync(reader, "example").GetAwaiter().GetResult()
        ?? throw new InvalidOperationException("Zone parser returned null");
    Require(records.Count == 1 && records[0].Name == @"a\..example",
        "Escaped trailing period was misclassified as FQDN termination");
});
Test("DNS parent check ignores periods inside labels", () =>
{
    var checker = typeof(DnsDatagram).GetMethod("IsSubDomainName",
        System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("DNS parent helper is missing");

    bool IsChild(string name, string parent) =>
        (bool)checker.Invoke(null, [name, parent])!;

    Require(IsChild("host.example", "example"), "Real subdomain not recognized");
    Require(IsChild(@"x\.y.example", "example"), "Real parent of escaped label not recognized");
    Require(!IsChild(@"x\.example", "example"), "Literal period mistaken for parent boundary");
    Require(!IsChild("example", "example"), "Equal names are not strict subdomains");
    Require(!IsChild("example", ""), "Root suffix special case changed");
});
Test("Zone-file write and read preserve escaped owner name", () =>
{
    var rr = new DnsResourceRecord(@"a\.example", DnsResourceRecordType.A,
        DnsClass.IN, 60, new DnsARecordData(System.Net.IPAddress.Parse("192.0.2.1")));
    using StringWriter writer = new();
    ZoneFile.WriteZoneFileToAsync(writer, "example", [rr]).GetAwaiter().GetResult();
    using StringReader reader = new(writer.ToString());
    var records = ZoneFile.ReadZoneFileFromAsync(reader, "example").GetAwaiter().GetResult()
        ?? throw new InvalidOperationException("Zone parser returned null");
    Require(records.Count == 1 && records[0].Name == rr.Name,
        "Export/import changed escaped DNS owner name");
});
Test("Encoded-domain length matches wire length", () =>
    Require(DnsDatagram.GetSerializeDomainNameLength(@"a\.b.example") == 13,
        "Wrong encoded name size"));
Test("Ordinary names decode and serialize without changes", () =>
    CheckRoundTrip(Convert.FromHexString("03777777076578616d706c6503636f6d00")));
Test("Literal period and backslash decode and serialize without changes", () =>
    CheckRoundTrip(Convert.FromHexString("05612e625c6300")));
Test("Maximum wire name with escaped label octets", () =>
{
    using MemoryStream name = new();
    foreach (int count in new[] {63, 63, 63, 61})
    {
        name.WriteByte((byte)count);
        for (int i = 0; i < count; i++)
            name.WriteByte((byte)'.');
    }
    name.WriteByte(0);
    Require(name.Length == 255, "Test must construct maximum RFC 1035 name");
    CheckRoundTrip(name.ToArray());
});
Test("BUG-04 invalid-label serialization regression", () =>
    CheckDatagramRoundTrip("12340100000100000000000105576c61692e0475657374000001000100002c04010008000f0004c0000201"));
Test("BUG-04 truncated serialization regression", () =>
    CheckDatagramRoundTrip("123481400000000000010000052e6c61696e04746573740017010001c00c002a000152348180000100028080"));
Test("BUG-06 RRSIG serialization regression", () =>
    CheckDatagramRoundTrip("12348580000100010000000005706c61696e042e00010000002e0001c00c002e00010000003c005e696e773594230d020000003c010001e8000000000000000000123485800003000100000000050000000000000000000000000000000000000000010000003c005e00010d021300003c77359400713fb30004d205706c61696e0474657374"));
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


static void CheckDatagramRoundTrip(string hex)
{
    using MemoryStream input = new(Convert.FromHexString(hex), writable: false);
    DnsDatagram parsed = DnsDatagram.ReadFrom(input);
    Require(parsed.ParsingException is null, "Original DNS packet rejected");
    using MemoryStream output = new();
    parsed.WriteTo(output);
    output.Position = 0;
    DnsDatagram reparsed = DnsDatagram.ReadFrom(output);
    Require(reparsed.ParsingException is null, "Serialized DNS packet rejected");
    Require(parsed.Identifier == reparsed.Identifier &&
        parsed.Question.Count == reparsed.Question.Count &&
        parsed.Answer.Count == reparsed.Answer.Count &&
        parsed.Authority.Count == reparsed.Authority.Count &&
        parsed.Additional.Count == reparsed.Additional.Count,
        "DNS header or section count changed");
}
