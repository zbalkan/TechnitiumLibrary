using System.Text.Json;
using TechnitiumLibrary.Net.Dns;

if (args.Length != 1)
{
    Console.Error.WriteLine("Usage: NameRoundTrip <wire-name.bin>");
    return 2;
}

byte[] original = File.ReadAllBytes(args[0]);
using MemoryStream input = new(original, writable: false);
string name = DnsDatagram.DeserializeDomainName(input);
if (input.Position != original.Length)
    throw new InvalidOperationException("Decoder did not consume full wire name.");
using MemoryStream output = new();
DnsDatagram.SerializeDomainName(name.AsSpan(), output);
Console.WriteLine(JsonSerializer.Serialize(new
{
    decoded = name,
    input_hex = Convert.ToHexString(original).ToLowerInvariant(),
    encoded_hex = Convert.ToHexString(output.ToArray()).ToLowerInvariant()
}));
return 0;
