using TechnitiumLibrary.Net.Dns;

using MemoryStream stream = new();
List<DnsDomainOffset> offsets = [];
DnsDatagram.SerializeDomainName("\u00C0.example", stream, offsets);
long secondOffset = stream.Position;
DnsDatagram.SerializeDomainName("\u00E0.example", stream, offsets);
stream.Position = secondOffset;
string actual = DnsDatagram.DeserializeDomainName(stream);
Console.WriteLine($"Baseline master decoded second domain as: {actual}");
Console.WriteLine($"Original byte 0xE0, decoded byte: 0x{(int)actual[0]:X2}");
if (actual == "\u00C0.example")
{
    Console.WriteLine("CONFIRMED: pre-existing Unicode case folding corrupts high-octet DNS compression.");
    return 0;
}
Console.Error.WriteLine("No pre-existing mismatch observed; investigate audit assumptions.");
return 1;
