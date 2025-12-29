using System.Linq;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Dns
{
    internal static class DnssecUtilities
    {
        /// <summary>
        /// Attempts to obtain DS information for the given owner name.
        /// - First checks DS / NSEC in the referral response itself.
        /// - If none present, performs a cache lookup.
        /// Does not validate DNSSEC — only reports trust-state signals.
        /// </summary>
        public static async Task<DsLookupResult> TryGetDSFromResponseAsync(
            DnsDatagram response,
            string owner,
            IDnsCache cache)
        {
            //
            // 1) Look for DS RRset in referral authority section
            //
            var dsInReferral = response.Authority
                .Where(r =>
                    r.Type == DnsResourceRecordType.DS &&
                    r.Name.Equals(owner, System.StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (dsInReferral.Count > 0)
                return DsLookupResult.FromRecords(dsInReferral);

            //
            // 2) Look for unsigned-zone proof via NSEC / NSEC3
            //
            if (response.Authority.Any(r =>
                    (r.Type == DnsResourceRecordType.NSEC ||
                     r.Type == DnsResourceRecordType.NSEC3) &&
                    r.Name.Equals(owner, System.StringComparison.OrdinalIgnoreCase)))
            {
                return DsLookupResult.UnsignedZone();
            }

            //
            // 3) No DS signals in referral → consult cache
            //
            var cached = await cache.QueryAsync(
                new DnsDatagram(
                    0, false, DnsOpcode.StandardQuery,
                    false, false, false, false, false, false,
                    DnsResponseCode.NoError,
                    new[] {
                        new DnsQuestionRecord(owner, DnsResourceRecordType.DS, DnsClass.IN)
                    }),
                serveStale: false,
                findClosestNameServers: false,
                resetExpiry: false);

            if (cached is null)
                return DsLookupResult.NoDecision();

            // Cached unsigned proof
            if (cached.Authority.Any(r =>
                    r.Type == DnsResourceRecordType.SOA ||
                    r.Type == DnsResourceRecordType.NSEC ||
                    r.Type == DnsResourceRecordType.NSEC3))
            {
                return DsLookupResult.UnsignedZone();
            }

            // Cached DS RRset
            var cachedDs = cached.Answer
                .Where(r => r.Type == DnsResourceRecordType.DS)
                .ToList();

            if (cachedDs.Count > 0)
                return DsLookupResult.FromRecords(cachedDs);

            return DsLookupResult.NoDecision();
        }
    }
}