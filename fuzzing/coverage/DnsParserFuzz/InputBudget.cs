namespace DnsParserFuzz;

internal static class InputBudget
{
    internal const int MaxBytes = ushort.MaxValue;

    // Enforce the cap while reading: CopyTo followed by a size check
    // would already have allocated an arbitrarily large memory buffer.
    internal static byte[]? ReadCapped(Stream input)
    {
        using MemoryStream collected = new();
        Span<byte> chunk = stackalloc byte[4096];
        int length;
        while ((length = input.Read(chunk)) > 0)
        {
            if (collected.Length + length > MaxBytes)
                return null;
            collected.Write(chunk[..length]);
        }
        return collected.ToArray();
    }
}
