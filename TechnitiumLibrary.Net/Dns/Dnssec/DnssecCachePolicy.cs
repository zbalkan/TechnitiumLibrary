/*
Technitium Library
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)
*/

using System;
using System.Collections.Generic;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Dns.Dnssec
{
    /// <summary>
    /// The rules a cache must apply to records carrying negative trust anchor provenance.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These are exported because <see cref="IDnsCache"/> places obligations on implementations
    /// that supply their own read path, and an obligation stated in prose but implemented only
    /// privately produces two implementations that drift. <see cref="DnsCache"/> applies exactly
    /// these methods, so a cache that calls them behaves identically to the reference
    /// implementation by construction rather than by careful reading.
    /// </para>
    ///
    /// <para>
    /// This matters in practice: a cache that derives from <see cref="DnsCache"/> but overrides
    /// its query and maintenance methods inherits none of this behaviour, and is in the same
    /// position as one implementing <see cref="IDnsCache"/> from scratch.
    /// </para>
    /// </remarks>
    public static class DnssecCachePolicy
    {
        /// <summary>
        /// Determines whether any of the supplied anchors has expired.
        /// </summary>
        /// <remarks>
        /// A record admitted under a negative trust anchor was accepted only because validation
        /// was suspended. Once the anchor lapses that justification is gone, so the record must
        /// stop being served rather than wait out its TTL - otherwise the anchor's expiry, which is
        /// the mechanism bounding how long validation stays off, has no effect on data already
        /// cached.
        /// </remarks>
        public static bool HasExpiredNegativeTrustAnchor(IReadOnlyList<NegativeTrustAnchorInfo> anchors)
        {
            if (anchors is null)
                return false;

            DateTimeOffset nowUtc = DateTimeOffset.UtcNow;

            foreach (NegativeTrustAnchorInfo anchor in anchors)
            {
                if ((anchor is not null) && (anchor.ExpiresOnUtc <= nowUtc))
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Determines whether any record in the supplied sections was accepted under an anchor
        /// that has since expired, including records nested inside a special cache record.
        /// </summary>
        public static bool HasExpiredNegativeTrustAnchor(params IReadOnlyList<DnsResourceRecord>[] sections)
        {
            if (sections is null)
                return false;

            DateTimeOffset nowUtc = DateTimeOffset.UtcNow;

            foreach (IReadOnlyList<DnsResourceRecord> records in sections)
            {
                if (records is null)
                    continue;

                foreach (DnsResourceRecord record in records)
                {
                    NegativeTrustAnchorInfo anchor = record.GetDnssecCacheMetadata().AppliedNegativeTrustAnchor;
                    if ((anchor is not null) && (anchor.ExpiresOnUtc <= nowUtc))
                        return true;

                    if ((record.RDATA is DnsCache.DnsSpecialCacheRecordData specialRecord) && HasExpiredNegativeTrustAnchor(specialRecord))
                        return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Determines whether a special cache record, or anything it wraps, was accepted under an
        /// anchor that has since expired.
        /// </summary>
        public static bool HasExpiredNegativeTrustAnchor(DnsCache.DnsSpecialCacheRecordData specialRecord)
        {
            if (specialRecord is null)
                return false;

            return HasExpiredNegativeTrustAnchor(specialRecord.AppliedNegativeTrustAnchors) ||
                HasExpiredNegativeTrustAnchor(specialRecord.OriginalAnswer, specialRecord.OriginalAuthority, specialRecord.OriginalAdditional);
        }

        /// <summary>
        /// Determines whether a cached response may set the AD bit.
        /// </summary>
        /// <remarks>
        /// True only when there is data to vouch for and every non-RRSIG, non-OPT record in it
        /// validated to <see cref="DnssecStatus.Secure"/>. A record demoted by a negative trust
        /// anchor is <see cref="DnssecStatus.Insecure"/>, so this also satisfies RFC 7646
        /// section 6 - but by consequence rather than by naming anchors, and a cache that
        /// derives AD any other way must check anchors explicitly.
        /// </remarks>
        public static bool CanSetAuthenticData(IReadOnlyList<DnsResourceRecord> answer, IReadOnlyList<DnsResourceRecord> authority)
        {
            bool foundData = false;

            foreach (IReadOnlyList<DnsResourceRecord> records in new[] { answer, authority })
            {
                if (records is null)
                    continue;

                foreach (DnsResourceRecord record in records)
                {
                    if ((record.Type == DnsResourceRecordType.RRSIG) || (record.Type == DnsResourceRecordType.OPT))
                        continue;

                    foundData = true;

                    if (record.DnssecStatus != DnssecStatus.Secure)
                        return false;
                }
            }

            return foundData;
        }

        /// <summary>
        /// Reattaches response-level anchor provenance to a response reconstructed from cache.
        /// </summary>
        /// <remarks>
        /// Only provenance is restored. Whether an EDE 33 option reaches the client is a
        /// presentation decision owned by the consuming application - see deviation D3 on
        /// <see cref="INegativeTrustAnchorProvider"/> - so this deliberately does not emit one,
        /// and cannot re-add an option a forwarded or original response already carried.
        /// </remarks>
        public static DnsDatagram RestoreNegativeTrustAnchorAnnotations(DnsDatagram response, IReadOnlyList<NegativeTrustAnchorInfo> anchors)
        {
            if ((response is null) || (anchors is null))
                return response;

            foreach (NegativeTrustAnchorInfo anchor in anchors)
            {
                if (anchor is not null)
                    response.AddAppliedNegativeTrustAnchor(anchor);
            }

            return response;
        }
    }
}
