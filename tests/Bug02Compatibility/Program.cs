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
Test("Independent wire-label and presentation oracle", () =>
{
    Random random = new(15112026);
    for (int n = 0; n < 1024; n++)
    {
        byte[][] labels = RandomLabels(random);
        byte[] wire = EncodeWireLabels(labels);
        string expected = ReferencePresentation(labels);
        using MemoryStream input = new(wire, writable: false);
        string actual = DnsDatagram.DeserializeDomainName(input);
        Require(actual == expected, $"Presentation differs for {Convert.ToHexString(wire)}");
        Require(DnsDatagram.GetSerializeDomainNameLength(actual) == wire.Length,
            "Reported encoded size differs from reference");
        using MemoryStream output = new();
        DnsDatagram.SerializeDomainName(actual, output);
        Require(output.ToArray().AsSpan().SequenceEqual(wire),
            "Encoding differs from independently generated wire data");
    }
});
Test("Independent DNSSEC canonical ordering oracle", () =>
{
    Random random = new(16712026);
    for (int n = 0; n < 1024; n++)
    {
        byte[][] left = RandomLabels(random);
        byte[][] right = RandomLabels(random);
        int expected = Math.Sign(ReferenceCanonicalComparison(left, right));
        int actual = Math.Sign(DnsNSECRecordData.CanonicalComparison(
            ReferencePresentation(left), ReferencePresentation(right)));
        Require(actual == expected, "Canonical NSEC order disagrees with raw-label oracle");
    }
});
Test("Random compressed suffixes preserve literal label octets", () =>
{
    Random random = new(18012026);
    byte[] alphabet = [(byte)'a', (byte)'A', (byte)'b', (byte)'0',
        (byte)'.', (byte)'\\', (byte)'-', (byte)'@', (byte)'*', 0];
    for (int i = 0; i < 1024; i++)
    {
        byte[][] suffixLabels = RandomLabels(random);
        for (int j = 0; j < suffixLabels.Length; j++)
            for (int k = 0; k < suffixLabels[j].Length; k++)
                suffixLabels[j][k] = alphabet[random.Next(alphabet.Length)];

        string suffix = ReferencePresentation(suffixLabels);
        string first = "x." + suffix;
        string second = "y." + suffix;
        using MemoryStream encoded = new();
        List<DnsDomainOffset> offsets = [];
        DnsDatagram.SerializeDomainName(first, encoded, offsets);
        long secondOffset = encoded.Position;
        DnsDatagram.SerializeDomainName(second, encoded, offsets);
        encoded.Position = secondOffset;
        string secondDecoded = DnsDatagram.DeserializeDomainName(encoded);
        Require(secondDecoded == second, $"Compression corrupted escaped label. Expected {second}, got {secondDecoded}");
    }
});
Test("Decoded escaped names remain separate from ordinary names under compression", () =>
{
    using MemoryStream encoded = new();
    List<DnsDomainOffset> entries = [];
    DnsDatagram.SerializeDomainName(@"a\.b.example", encoded, entries);
    long secondOffset = encoded.Position;
    DnsDatagram.SerializeDomainName("a.b.example", encoded, entries);
    encoded.Position = secondOffset;
    string parsed = DnsDatagram.DeserializeDomainName(encoded);
    Require(parsed == "a.b.example", $"Compression merged label boundaries: '{parsed}'");
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

static byte[][] RandomLabels(Random random)
{
    int count = random.Next(1, 5);
    byte[][] labels = new byte[count][];
    for (int i = 0; i < count; i++)
    {
        labels[i] = new byte[random.Next(1, 16)];
        random.NextBytes(labels[i]);
    }
    return labels;
}
static byte[] EncodeWireLabels(byte[][] labels)
{
    using MemoryStream output = new();
    foreach (byte[] label in labels)
    {
        output.WriteByte((byte)label.Length);
        output.Write(label);
    }
    output.WriteByte(0);
    return output.ToArray();
}
static string ReferencePresentation(byte[][] labels)
{
    System.Text.StringBuilder text = new();
    for (int i = 0; i < labels.Length; i++)
    {
        if (i > 0)
            text.Append('.');
        foreach (byte octet in labels[i])
        {
            if (octet is (byte)'.' or (byte)'\\')
                text.Append('\\');
            text.Append((char)octet);
        }
    }
    return text.ToString();
}
static int ReferenceCanonicalComparison(byte[][] a, byte[][] b)
{
    int min = Math.Min(a.Length, b.Length);
    for (int i = 1; i <= min; i++)
    {
        byte[] left = a[^i], right = b[^i];
        int common = Math.Min(left.Length, right.Length);
        for (int j = 0; j < common; j++)
        {
            int x = (left[j] >= 'A' && left[j] <= 'Z') ? left[j] + 32 : left[j];
            int y = (right[j] >= 'A' && right[j] <= 'Z') ? right[j] + 32 : right[j];
            if (x != y)
                return x.CompareTo(y);
        }
        if (left.Length != right.Length)
            return left.Length.CompareTo(right.Length);
    }
    return a.Length.CompareTo(b.Length);
}
