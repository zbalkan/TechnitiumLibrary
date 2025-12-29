using System.Collections.Generic;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Dns
{
    internal readonly struct DsLookupResult
    {
        public bool HasOutcome { get; }
        public IReadOnlyList<DnsResourceRecord>? DsRecords { get; }

        public bool IsUnsignedZone =>
            HasOutcome && DsRecords is null;

        public bool HasDsRecords =>
            HasOutcome && DsRecords is { Count: > 0 };

        public DsLookupResult(bool hasOutcome, IReadOnlyList<DnsResourceRecord>? ds)
        {
            HasOutcome = hasOutcome;
            DsRecords = ds;
        }

        public static DsLookupResult NoDecision() =>
            new DsLookupResult(false, null);

        public static DsLookupResult UnsignedZone() =>
            new DsLookupResult(true, null);

        public static DsLookupResult FromRecords(IReadOnlyList<DnsResourceRecord> ds) =>
            new DsLookupResult(true, ds);
    }
}
