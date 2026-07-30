/*
Technitium Library
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns.Dnssec;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Dns
{
    //Negative Caching of DNS Queries (DNS NCACHE) 
    //https://datatracker.ietf.org/doc/html/rfc2308

    public class DnsCache : IDnsCache
    {
        #region variables

        readonly static DnsCacheEntry ROOT_CACHE_ENTRY = DnsCacheEntry.GetRootCacheEntry();

        const uint FAILURE_RECORD_TTL = 60u;
        const uint NEGATIVE_RECORD_TTL = 300u;
        const uint MINIMUM_RECORD_TTL = 10u;
        const uint MAXIMUM_RECORD_TTL = 3600u;
        const uint SERVE_STALE_TTL = 0u;
        const uint SERVE_STALE_TTL_MAX = 7 * 24 * 60 * 60; //7 days cap on serve stale
        const uint SERVE_STALE_ANSWER_TTL = 30u;
        const uint SERVE_STALE_ANSWER_TTL_MAX = 300; //5 mins

        uint _failureRecordTtl;
        uint _negativeRecordTtl;
        uint _minimumRecordTtl;
        uint _maximumRecordTtl;
        uint _serveStaleTtl;
        uint _serveStaleAnswerTtl;

        readonly ConcurrentDictionary<string, DnsCacheEntry> _cache = new ConcurrentDictionary<string, DnsCacheEntry>(1, 5);

        #endregion

        #region constructor

        public DnsCache()
            : this(FAILURE_RECORD_TTL, NEGATIVE_RECORD_TTL, MINIMUM_RECORD_TTL, MAXIMUM_RECORD_TTL, SERVE_STALE_TTL, SERVE_STALE_ANSWER_TTL)
        {
            //cache root hints to avoid priming query for casual recursive resolution tasks
            _cache[""] = ROOT_CACHE_ENTRY;
        }

        protected DnsCache(uint failureRecordTtl, uint negativeRecordTtl, uint minimumRecordTtl, uint maximumRecordTtl, uint serveStaleTtl, uint serveStaleAnswerTtl)
        {
            _failureRecordTtl = failureRecordTtl;
            _negativeRecordTtl = negativeRecordTtl;
            _minimumRecordTtl = minimumRecordTtl;
            _maximumRecordTtl = maximumRecordTtl;
            _serveStaleTtl = serveStaleTtl;
            _serveStaleAnswerTtl = serveStaleAnswerTtl;
        }

        #endregion

        #region protected

        /// <summary>
        /// Stores resolver cache records using the cache implementation's native indexing,
        /// persistence, expiration, and invalidation model.
        /// </summary>
        /// <remarks>
        /// Derived implementations must retain special cache records, including
        /// <see cref="DnsSpecialCacheRecordType.PositiveCache"/>. Composite positive responses are
        /// deliberately routed through this extension point so ECS variants, persistence, cache
        /// maintenance, and flushing remain owned by the cache implementation.
        /// </remarks>
        protected virtual void CacheRecords(IReadOnlyList<DnsResourceRecord> resourceRecords, NetworkAddress eDnsClientSubnet, DnsDatagramMetadata responseMetadata)
        {
            if (resourceRecords.Count == 1)
            {
                DnsResourceRecord resourceRecord = resourceRecords[0];

                if (resourceRecord.Type == DnsResourceRecordType.DNAME)
                    return; //DnsCache does not support DNAME

                DnsCacheEntry entry = _cache.GetOrAdd(resourceRecord.Name.ToLowerInvariant(), delegate (string key)
                {
                    return new DnsCacheEntry(1);
                });

                entry.SetRecords(resourceRecords);
            }
            else
            {
                Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> cacheEntries = DnsResourceRecord.GroupRecords(resourceRecords);

                //add grouped entries into cache
                foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> cacheEntry in cacheEntries)
                {
                    bool foundDNAME = false;

                    foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> cacheTypeEntry in cacheEntry.Value)
                    {
                        if (cacheTypeEntry.Key == DnsResourceRecordType.DNAME)
                        {
                            foundDNAME = true;
                            break;
                        }
                    }

                    if (foundDNAME)
                        continue; //DnsCache does not support DNAME

                    DnsCacheEntry entry = _cache.GetOrAdd(cacheEntry.Key.ToLowerInvariant(), delegate (string key)
                    {
                        return new DnsCacheEntry(cacheEntry.Value.Count);
                    });

                    foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> cacheTypeEntry in cacheEntry.Value)
                        entry.SetRecords(cacheTypeEntry.Value);
                }
            }
        }

        protected static DnsResourceRecordInfo GetRecordInfo(DnsResourceRecord record)
        {
            if (record.Tag is not DnsResourceRecordInfo recordInfo)
            {
                recordInfo = new DnsResourceRecordInfo();
                record.Tag = recordInfo;
            }

            return recordInfo;
        }

        #endregion

        #region private

        internal static string GetParentZone(string domain, bool returnRoot = false)
        {
            if (domain.Length > 0)
            {
                int i = domain.IndexOf('.');
                if (i > -1)
                    return domain.Substring(i + 1);

                if (returnRoot)
                    return string.Empty;
            }

            return null;
        }

        private void InternalCacheRecords(IReadOnlyList<DnsResourceRecord> resourceRecords, NetworkAddress eDnsClientSubnet, DnsDatagramMetadata responseMetadata)
        {
            foreach (DnsResourceRecord resourceRecord in resourceRecords)
            {
                resourceRecord.NormalizeName();
                if (resourceRecord.RDATA is DnsSpecialCacheRecordData specialRecord)
                    resourceRecord.SetDnsCacheWriteContext(specialRecord.DnsCacheWriteContext);

                IReadOnlyList<DnsResourceRecord> glueRecords = GetRecordInfo(resourceRecord).GlueRecords;
                if (glueRecords is not null)
                {
                    foreach (DnsResourceRecord glueRecord in glueRecords)
                        glueRecord.NormalizeName();
                }
            }

            CacheRecords(resourceRecords, eDnsClientSubnet, responseMetadata);
        }

        private IReadOnlyList<DnsResourceRecord> GetClosestReferralNameServers(string domain, bool dnssecOk)
        {
            domain = domain.ToLowerInvariant();

            do
            {
                if (_cache.TryGetValue(domain, out DnsCacheEntry entry))
                {
                    IReadOnlyList<DnsResourceRecord> records = entry.QueryRecords(DnsResourceRecordType.PARENT_NS, true);
                    if ((records.Count > 0) && (records[0].Type == DnsResourceRecordType.NS))
                    {
                        if (dnssecOk)
                        {
                            if (records[0].DnssecStatus != DnssecStatus.Disabled) //dont return NS records for Disabled status since DO flag is set
                                return AddDSRecordsTo(entry, records);
                        }
                        else
                        {
                            return records;
                        }
                    }
                }

                domain = GetParentZone(domain, true);
            }
            while (domain is not null);

            return null;
        }

        private static IReadOnlyList<DnsResourceRecord> AddDSRecordsTo(DnsCacheEntry entry, IReadOnlyList<DnsResourceRecord> nsRecords)
        {
            IReadOnlyList<DnsResourceRecord> records = entry.QueryRecords(DnsResourceRecordType.DS, true);
            if ((records.Count > 0) && (records[0].Type == DnsResourceRecordType.DS))
            {
                List<DnsResourceRecord> newNSRecords = new List<DnsResourceRecord>(nsRecords.Count + records.Count + 1);

                newNSRecords.AddRange(nsRecords);
                newNSRecords.AddRange(records);

                IReadOnlyList<DnsResourceRecord> rrsigRecords = GetRecordInfo(records[0]).RRSIGRecords;
                if (rrsigRecords is not null)
                    newNSRecords.AddRange(rrsigRecords);

                return newNSRecords;
            }

            //no DS records found check for NSEC records
            IReadOnlyList<DnsResourceRecord> nsecRecords = GetRecordInfo(nsRecords[0]).NSECRecords;
            if (nsecRecords is not null)
            {
                List<DnsResourceRecord> newNSRecords = new List<DnsResourceRecord>(nsRecords.Count + (nsecRecords.Count * 2));

                newNSRecords.AddRange(nsRecords);

                foreach (DnsResourceRecord nsecRecord in nsecRecords)
                {
                    newNSRecords.Add(nsecRecord);

                    IReadOnlyList<DnsResourceRecord> rrsigRecords = GetRecordInfo(nsecRecord).RRSIGRecords;
                    if (rrsigRecords is not null)
                        newNSRecords.AddRange(rrsigRecords);
                }

                return newNSRecords;
            }

            //found nothing; return original NS records
            return nsRecords;
        }

        private void ResolveCNAME(DnsQuestionRecord question, DnsResourceRecord lastCNAME, List<DnsResourceRecord> answerRecords)
        {
            int queryCount = 0;

            do
            {
                string cnameDomain = (lastCNAME.RDATA as DnsCNAMERecordData).Domain;
                if (lastCNAME.Name.Equals(cnameDomain, StringComparison.OrdinalIgnoreCase))
                    break; //loop detected

                if (!_cache.TryGetValue(cnameDomain.ToLowerInvariant(), out DnsCacheEntry entry))
                    break;

                IReadOnlyList<DnsResourceRecord> records = entry.QueryRecords(question.Type, true);
                if (records.Count < 1)
                    break;

                DnsResourceRecord lastRR = records[records.Count - 1];
                if (lastRR.Type != DnsResourceRecordType.CNAME)
                {
                    answerRecords.AddRange(records);
                    break; //cname was resolved
                }

                foreach (DnsResourceRecord answerRecord in answerRecords)
                {
                    if (answerRecord.Type != DnsResourceRecordType.CNAME)
                        continue;

                    if (answerRecord.RDATA.Equals(lastRR.RDATA))
                        return; //loop detected
                }

                answerRecords.AddRange(records);

                lastCNAME = lastRR;
            }
            while (++queryCount < DnsClient.MAX_CNAME_HOPS);
        }

        private List<DnsResourceRecord> GetAdditionalRecords(IReadOnlyList<DnsResourceRecord> refRecords)
        {
            List<DnsResourceRecord> additionalRecords = new List<DnsResourceRecord>();

            foreach (DnsResourceRecord refRecord in refRecords)
            {
                switch (refRecord.Type)
                {
                    case DnsResourceRecordType.NS:
                        DnsNSRecordData nsRecord = refRecord.RDATA as DnsNSRecordData;
                        if (nsRecord is not null)
                            ResolveAdditionalRecords(refRecord, nsRecord.NameServer, additionalRecords);

                        break;

                    case DnsResourceRecordType.MX:
                        DnsMXRecordData mxRecord = refRecord.RDATA as DnsMXRecordData;
                        if (mxRecord is not null)
                            ResolveAdditionalRecords(refRecord, mxRecord.Exchange, additionalRecords);

                        break;

                    case DnsResourceRecordType.SRV:
                        DnsSRVRecordData srvRecord = refRecord.RDATA as DnsSRVRecordData;
                        if (srvRecord is not null)
                            ResolveAdditionalRecords(refRecord, srvRecord.Target, additionalRecords);

                        break;
                }
            }

            return additionalRecords;
        }

        private void ResolveAdditionalRecords(DnsResourceRecord refRecord, string domain, List<DnsResourceRecord> additionalRecords)
        {
            IReadOnlyList<DnsResourceRecord> glueRecords = GetRecordInfo(refRecord).GlueRecords;
            if (glueRecords is not null)
            {
                bool added = false;

                foreach (DnsResourceRecord glueRecord in glueRecords)
                {
                    if (!glueRecord.IsStale && ((glueRecord.AppliedNegativeTrustAnchor is null) || (glueRecord.AppliedNegativeTrustAnchor.ExpiresOnUtc > DateTimeOffset.UtcNow)))
                    {
                        added = true;
                        additionalRecords.Add(glueRecord);
                    }
                }

                if (added)
                    return;
            }

            if (_cache.TryGetValue(domain.ToLowerInvariant(), out DnsCacheEntry entry))
            {
                IReadOnlyList<DnsResourceRecord> glueAs = entry.QueryRecords(DnsResourceRecordType.A, true);
                if ((glueAs.Count > 0) && (glueAs[0].Type == DnsResourceRecordType.A))
                    additionalRecords.AddRange(glueAs);

                IReadOnlyList<DnsResourceRecord> glueAAAAs = entry.QueryRecords(DnsResourceRecordType.AAAA, true);
                if ((glueAAAAs.Count > 0) && (glueAAAAs[0].Type == DnsResourceRecordType.AAAA))
                    additionalRecords.AddRange(glueAAAAs);
            }
        }

        private static bool CanSetAuthenticData(IReadOnlyList<DnsResourceRecord> answer, IReadOnlyList<DnsResourceRecord> authority)
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

        private static bool HasSamePolicyIdentity(DnsCacheWriteContext left, DnsCacheWriteContext right)
        {
            if ((left is null) || (right is null))
                return left is null && right is null;
            return (left.PolicyScopeId == right.PolicyScopeId) &&
                (left.PolicyRevisionId == right.PolicyRevisionId) &&
                (left.DnssecPolicyGeneration == right.DnssecPolicyGeneration);
        }

        private static bool IsPolicyGenerationCompatible(DnsDatagram request, IReadOnlyList<DnsResourceRecord> records)
        {
            return IsPolicyGenerationCompatible(request, [records]);
        }

        private static DnsCacheWriteContext GetRetainedPolicyContext(DnsDatagram request, params IReadOnlyList<DnsResourceRecord>[] sections)
        {
            if (request.DnsCacheWriteContext is not null)
                return request.DnsCacheWriteContext;
            foreach (IReadOnlyList<DnsResourceRecord> section in sections)
                if (section is not null)
                    foreach (DnsResourceRecord record in section)
                        return record.GetDnssecCacheMetadata().DnsCacheWriteContext;
            return null;
        }

        private static bool IsPolicyGenerationCompatible(DnsDatagram request, params IReadOnlyList<DnsResourceRecord>[] sections)
        {
            DnsCacheWriteContext expectedContext = request.DnsCacheWriteContext;
            bool foundContext = expectedContext is not null;
            foreach (IReadOnlyList<DnsResourceRecord> section in sections)
            {
                if (section is null)
                    continue;
                foreach (DnsResourceRecord record in section)
                {
                    DnsCacheWriteContext recordContext = record.GetDnssecCacheMetadata().DnsCacheWriteContext;
                    if (!foundContext)
                    {
                        expectedContext = recordContext;
                        foundContext = true;
                    }
                    else if (!HasSamePolicyIdentity(expectedContext, recordContext))
                    {
                        return false;
                    }
                }
            }
            return true;
        }

        private static bool HasExpiredNegativeTrustAnchor(IReadOnlyList<NegativeTrustAnchorInfo> anchors)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            if (anchors is not null)
            {
                foreach (NegativeTrustAnchorInfo anchor in anchors)
                    if ((anchor is not null) && (anchor.ExpiresOnUtc <= now))
                        return true;
            }
            return false;
        }

        private static bool HasExpiredNegativeTrustAnchor(params IReadOnlyList<DnsResourceRecord>[] sections)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            foreach (IReadOnlyList<DnsResourceRecord> records in sections)
            {
                if (records is null)
                    continue;
                foreach (DnsResourceRecord record in records)
                    if (((record.AppliedNegativeTrustAnchor is not null) && (record.AppliedNegativeTrustAnchor.ExpiresOnUtc <= now)) ||
                        ((record.RDATA is DnsSpecialCacheRecordData specialRecord) && HasExpiredNegativeTrustAnchor(specialRecord)))
                        return true;
            }
            return false;
        }

        private static bool HasExpiredNegativeTrustAnchor(DnsSpecialCacheRecordData specialRecord)
        {
            return HasExpiredNegativeTrustAnchor(specialRecord.AppliedNegativeTrustAnchors) ||
                HasExpiredNegativeTrustAnchor(specialRecord.OriginalAnswer, specialRecord.OriginalAuthority, specialRecord.OriginalAdditional);
        }

        /// <summary>
        /// Emits EDE INFO-CODE 33 (Negative Trust Anchor, RFC 9567) for a query that requested
        /// DNSSEC validation whenever the response's provenance shows a negative trust anchor was
        /// applied. Gated on <see cref="DnsDatagram.DnssecOk"/> so a client that never asked for
        /// DNSSEC validation is never told about a validation posture it did not request -
        /// attaching this diagnostic unconditionally would leak validation-outcome signalling to a
        /// non-validating query the same way suppressing it unconditionally would hide it from a
        /// validating one.
        /// </summary>
        private static void AddNegativeTrustAnchorExtendedErrors(DnsDatagram request, DnsDatagram response)
        {
            if (!request.DnssecOk)
                return;

            foreach (NegativeTrustAnchorInfo anchor in response.AppliedNegativeTrustAnchors)
                response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NegativeTrustAnchor, "Negative trust anchor: " + anchor.Name + "; expires " + anchor.ExpiresOnUtc.UtcDateTime.ToString("o"));
        }

        private static DnsDatagram RestoreNegativeTrustAnchorAnnotations(DnsDatagram request, DnsDatagram response, IReadOnlyList<NegativeTrustAnchorInfo> anchors)
        {
            if (anchors is not null)
                foreach (NegativeTrustAnchorInfo anchor in anchors)
                    if (anchor is not null)
                        response.AddAppliedNegativeTrustAnchor(anchor);

            AddNegativeTrustAnchorExtendedErrors(request, response);

            return response;
        }

        /// <summary>
        /// Reconstructs a cached special response while enforcing DNSSEC provenance,
        /// negative-trust-anchor expiry, and AD-bit semantics. Derived cache
        /// implementations should use this helper for <see cref="DnsSpecialCacheRecordType.PositiveCache"/>
        /// and other special cache records instead of duplicating reconstruction logic.
        /// </summary>
        /// <returns>The reconstructed response, or null when the cached policy dependency is no longer valid.</returns>
        protected static DnsDatagram GetSpecialCachedResponse(DnsDatagram request, DnsSpecialCacheRecordData specialRecord)
        {
            if ((request.DnsCacheWriteContext is not null) &&
                ((specialRecord.DnsCacheWriteContext is null) ||
                 (specialRecord.DnsCacheWriteContext.PolicyScopeId != request.DnsCacheWriteContext.PolicyScopeId) ||
                 (specialRecord.DnsCacheWriteContext.PolicyRevisionId != request.DnsCacheWriteContext.PolicyRevisionId) ||
                 (specialRecord.DnsCacheWriteContext.DnssecPolicyGeneration != request.DnsCacheWriteContext.DnssecPolicyGeneration)))
            {
                return null;
            }

            if (HasExpiredNegativeTrustAnchor(specialRecord))
                return null;

            if (request.DnssecOk)
            {
                foreach (DnsResourceRecord originalAuthority in specialRecord.OriginalAuthority)
                    if (originalAuthority.DnssecStatus == DnssecStatus.Disabled)
                        return null;

                IReadOnlyList<DnsResourceRecord> answer = request.CheckingDisabled ? specialRecord.OriginalAnswer : specialRecord.Answer;
                IReadOnlyList<DnsResourceRecord> authority = request.CheckingDisabled ? specialRecord.OriginalAuthority : specialRecord.Authority;
                IReadOnlyList<DnsResourceRecord> additional = request.CheckingDisabled ? specialRecord.OriginalAdditional : null;
                if (!IsPolicyGenerationCompatible(request, answer, authority, additional))
                    return null;
                foreach (IReadOnlyList<DnsResourceRecord> section in new[] { answer, authority, additional })
                    foreach (DnsResourceRecord record in section ?? Array.Empty<DnsResourceRecord>())
                        if (record.IsStale)
                            return null;
                DnsCacheWriteContext retainedContext = GetRetainedPolicyContext(request, answer, authority, additional);
                if ((request.DnsCacheWriteContext is null) && ((answer?.Count ?? 0) + (authority?.Count ?? 0) + (additional?.Count ?? 0) > 0) && !HasSamePolicyIdentity(retainedContext, specialRecord.DnsCacheWriteContext))
                    return null;
                IReadOnlyList<NegativeTrustAnchorInfo> anchors = GetResponseOnlyNegativeTrustAnchorsForRetainedSections(specialRecord, answer, authority, additional);
                DnsDatagram response = new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, CanSetAuthenticData(answer, authority), request.CheckingDisabled, request.CheckingDisabled ? specialRecord.OriginalRCODE : specialRecord.RCODE, request.Question, answer, authority, additional, request.EDNS.UdpPayloadSize, EDnsHeaderFlags.DNSSEC_OK, specialRecord.EDnsOptions);
                response.SetDnsCacheWriteContext(retainedContext ?? specialRecord.DnsCacheWriteContext);
                return RestoreNegativeTrustAnchorAnnotations(request, response, anchors);
            }

            DnsDatagram noDnssecResponse = request.CheckingDisabled ?
                new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, true, specialRecord.OriginalRCODE, request.Question, specialRecord.OriginalNoDnssecAnswer, specialRecord.OriginalNoDnssecAuthority, specialRecord.OriginalAdditional, request.EDNS is null ? ushort.MinValue : request.EDNS.UdpPayloadSize, EDnsHeaderFlags.None, specialRecord.EDnsOptions) :
                new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, specialRecord.RCODE, request.Question, specialRecord.NoDnssecAnswer, specialRecord.NoDnssecAuthority, null, request.EDNS is null ? ushort.MinValue : request.EDNS.UdpPayloadSize, EDnsHeaderFlags.None, specialRecord.EDnsOptions);
            if (!IsPolicyGenerationCompatible(request, noDnssecResponse.Answer, noDnssecResponse.Authority, noDnssecResponse.Additional))
                return null;
            foreach (IReadOnlyList<DnsResourceRecord> section in new[] { noDnssecResponse.Answer, noDnssecResponse.Authority, noDnssecResponse.Additional })
                foreach (DnsResourceRecord record in section ?? Array.Empty<DnsResourceRecord>())
                    if (record.IsStale)
                        return null;
            DnsCacheWriteContext noDnssecRetainedContext = GetRetainedPolicyContext(request, noDnssecResponse.Answer, noDnssecResponse.Authority, noDnssecResponse.Additional);
            if ((request.DnsCacheWriteContext is null) && ((noDnssecResponse.Answer?.Count ?? 0) + (noDnssecResponse.Authority?.Count ?? 0) + (noDnssecResponse.Additional?.Count ?? 0) > 0) && !HasSamePolicyIdentity(noDnssecRetainedContext, specialRecord.DnsCacheWriteContext))
                return null;
            noDnssecResponse.SetDnsCacheWriteContext(noDnssecRetainedContext ?? specialRecord.DnsCacheWriteContext);
            return RestoreNegativeTrustAnchorAnnotations(request, noDnssecResponse, GetResponseOnlyNegativeTrustAnchorsForRetainedSections(specialRecord, noDnssecResponse.Answer, noDnssecResponse.Authority, noDnssecResponse.Additional));
        }

        private static IReadOnlyList<NegativeTrustAnchorInfo> GetResponseOnlyNegativeTrustAnchorsForRetainedSections(DnsSpecialCacheRecordData specialRecord, params IReadOnlyList<DnsResourceRecord>[] retainedSections)
        {
            List<NegativeTrustAnchorInfo> responseOnlyAnchors = new List<NegativeTrustAnchorInfo>();

            void Add(NegativeTrustAnchorInfo anchor)
            {
                if (anchor is null)
                    return;
                int index = responseOnlyAnchors.FindIndex(existing => existing.Name.Equals(anchor.Name, StringComparison.OrdinalIgnoreCase));
                if (index < 0)
                    responseOnlyAnchors.Add(anchor);
                else
                    responseOnlyAnchors[index] = responseOnlyAnchors[index].MergeMostRestrictive(anchor);
            }

            foreach (NegativeTrustAnchorInfo anchor in specialRecord.AppliedNegativeTrustAnchors)
                Add(anchor);

            //Discarded additional-only provenance does not affect AD and is not promoted to
            //response-only provenance. Retained additional records continue to carry it directly.
            foreach (IReadOnlyList<DnsResourceRecord> originalSection in new[] { specialRecord.OriginalAnswer, specialRecord.OriginalAuthority })
            {
                foreach (DnsResourceRecord originalRecord in originalSection)
                {
                    NegativeTrustAnchorInfo anchor = originalRecord.GetDnssecCacheMetadata().AppliedNegativeTrustAnchor;
                    if (anchor is null)
                        continue;

                    bool retained = false;
                    for (int retainedSectionIndex = 0; retainedSectionIndex < Math.Min(2, retainedSections.Length); retainedSectionIndex++)
                    {
                        IReadOnlyList<DnsResourceRecord> retainedSection = retainedSections[retainedSectionIndex];
                        foreach (DnsResourceRecord retainedRecord in retainedSection ?? Array.Empty<DnsResourceRecord>())
                        {
                            NegativeTrustAnchorInfo retainedAnchor = retainedRecord.GetDnssecCacheMetadata().AppliedNegativeTrustAnchor;
                            if (retainedAnchor.RepresentsDependency(anchor))
                            {
                                retained = true;
                                break;
                            }
                        }
                        if (retained)
                            break;
                    }

                    if (!retained)
                        Add(anchor);
                }
            }

            return responseOnlyAnchors;
        }

        /// <summary>
        /// Computes additional-section glue for a composite <see cref="DnsSpecialCacheRecordType.PositiveCache"/>
        /// answer. Ordinary special-cache records (negative/failure/bad/blocked) never carry
        /// meaningful glue and are returned unchanged; <see cref="GetSpecialCachedResponse"/> itself
        /// stays static and reconstruction-only so it does not depend on this cache instance's
        /// referral/glue lookups. The response's own OPT record (if any) is always preserved.
        /// </summary>
        private DnsDatagram AttachAdditionalForPositiveCache(DnsDatagram response, DnsSpecialCacheRecordData specialRecord, DnsResourceRecordType questionType)
        {
            if ((specialRecord.Type != DnsSpecialCacheRecordType.PositiveCache) || (response.Answer.Count == 0))
                return response;

            switch (questionType)
            {
                case DnsResourceRecordType.NS:
                case DnsResourceRecordType.MX:
                case DnsResourceRecordType.SRV:
                    break;

                default:
                    return response;
            }

            bool hasNonOptAdditional = false;
            foreach (DnsResourceRecord record in response.Additional)
            {
                if (record.Type != DnsResourceRecordType.OPT)
                {
                    hasNonOptAdditional = true;
                    break;
                }
            }

            if (hasNonOptAdditional)
                return response; //already carries glue; nothing to add

            List<DnsResourceRecord> glueRecords = GetAdditionalRecords(response.Answer);
            if (glueRecords.Count == 0)
                return response;

            List<DnsResourceRecord> newAdditional = new List<DnsResourceRecord>(glueRecords.Count + response.Additional.Count);
            newAdditional.AddRange(glueRecords);
            newAdditional.AddRange(response.Additional); //preserve the existing OPT record, if any

            return response.CloneRetainingResolverProvenance(additional: newAdditional);
        }

        #endregion

        #region public

        public virtual Task<DnsDatagram> QueryAsync(DnsDatagram request, bool serveStale = false, bool findClosestNameServers = false, bool resetExpiry = false)
        {
            DnsQuestionRecord question = request.Question[0];

            if (_cache.TryGetValue(question.Name.ToLowerInvariant(), out DnsCacheEntry entry))
            {
                IReadOnlyList<DnsResourceRecord> positiveCacheRecords = entry.QueryPositiveCache(question.Type);
                if (positiveCacheRecords.Count > 0)
                {
                    if (!IsPolicyGenerationCompatible(request, positiveCacheRecords))
                        goto beforeFindClosestNameServers;

                    DnsSpecialCacheRecordData positiveSpecialRecord = positiveCacheRecords[0].RDATA as DnsSpecialCacheRecordData;
                    DnsDatagram positiveCachedResponse = GetSpecialCachedResponse(request, positiveSpecialRecord);
                    if (positiveCachedResponse is not null)
                        return Task.FromResult(AttachAdditionalForPositiveCache(positiveCachedResponse, positiveSpecialRecord, question.Type));

                    goto beforeFindClosestNameServers; //cached policy dependency is no longer valid; dont retry via the ordinary lookup below
                }

                DnsResourceRecordType qtype;

                switch (question.Type)
                {
                    case DnsResourceRecordType.NS:
                        qtype = DnsResourceRecordType.CHILD_NS;
                        break;

                    case DnsResourceRecordType.PARENT_NS:
                        qtype = DnsResourceRecordType.NS;
                        break;

                    default:
                        qtype = question.Type;
                        break;
                }

                IReadOnlyList<DnsResourceRecord> answers = entry.QueryRecords(qtype, false);
                if (answers.Count > 0)
                {
                    if (!IsPolicyGenerationCompatible(request, answers))
                        goto beforeFindClosestNameServers;

                    DnsResourceRecord firstRR = answers[0];

                    if (firstRR.RDATA is DnsSpecialCacheRecordData dnsSpecialCacheRecord)
                    {
                        DnsDatagram specialCachedResponse = GetSpecialCachedResponse(request, dnsSpecialCacheRecord);
                        if (specialCachedResponse is not null)
                            return Task.FromResult(AttachAdditionalForPositiveCache(specialCachedResponse, dnsSpecialCacheRecord, question.Type));

                        goto beforeFindClosestNameServers;
                    }

                    DnsResourceRecord lastRR = answers[answers.Count - 1];
                    if ((lastRR.Type != question.Type) && (lastRR.Type == DnsResourceRecordType.CNAME) && (question.Type != DnsResourceRecordType.ANY))
                    {
                        List<DnsResourceRecord> newAnswers = new List<DnsResourceRecord>(answers.Count + 3);
                        newAnswers.AddRange(answers);

                        ResolveCNAME(question, lastRR, newAnswers);

                        answers = newAnswers;
                    }

                    IReadOnlyList<DnsResourceRecord> authority = null;

                    if (request.DnssecOk)
                    {
                        //DNSSEC enabled
                        foreach (DnsResourceRecord answer in answers)
                        {
                            if (answer.DnssecStatus == DnssecStatus.Disabled)
                                goto beforeFindClosestNameServers; //dont return answer when status is disabled since DO flag is set
                        }

                        //insert RRSIG records
                        List<DnsResourceRecord> newAnswers = new List<DnsResourceRecord>(answers.Count * 2);
                        List<DnsResourceRecord> newAuthority = null;

                        foreach (DnsResourceRecord answer in answers)
                        {
                            newAnswers.Add(answer);

                            DnsResourceRecordInfo answerRecordInfo = GetRecordInfo(answer);

                            IReadOnlyList<DnsResourceRecord> rrsigRecords = answerRecordInfo.RRSIGRecords;
                            if (rrsigRecords is not null)
                            {
                                newAnswers.AddRange(rrsigRecords);

                                foreach (DnsResourceRecord rrsigRecord in rrsigRecords)
                                {
                                    if (!DnsRRSIGRecordData.IsWildcard(rrsigRecord))
                                        continue;

                                    //add NSEC/NSEC3 for the wildcard proof
                                    if (newAuthority is null)
                                        newAuthority = new List<DnsResourceRecord>(2);

                                    IReadOnlyList<DnsResourceRecord> nsecRecords = answerRecordInfo.NSECRecords;
                                    if (nsecRecords is not null)
                                    {
                                        foreach (DnsResourceRecord nsecRecord in nsecRecords)
                                        {
                                            newAuthority.Add(nsecRecord);

                                            IReadOnlyList<DnsResourceRecord> nsecRRSIGRecords = GetRecordInfo(nsecRecord).RRSIGRecords;
                                            if (nsecRRSIGRecords is not null)
                                                newAuthority.AddRange(nsecRRSIGRecords);
                                        }
                                    }
                                }
                            }
                        }

                        answers = newAnswers;
                        authority = newAuthority;
                    }

                    IReadOnlyList<DnsResourceRecord> additional = null;

                    switch (question.Type)
                    {
                        case DnsResourceRecordType.NS:
                        case DnsResourceRecordType.MX:
                        case DnsResourceRecordType.SRV:
                            additional = GetAdditionalRecords(answers);
                            break;
                    }

                    if (HasExpiredNegativeTrustAnchor(answers, authority))
                        goto beforeFindClosestNameServers;
                    if (!IsPolicyGenerationCompatible(request, answers, authority, additional))
                        goto beforeFindClosestNameServers;

                    DnsDatagram cachedResponse = new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, CanSetAuthenticData(answers, authority), request.CheckingDisabled, DnsResponseCode.NoError, request.Question, answers, authority, additional);
                    cachedResponse.SetDnsCacheWriteContext(GetRetainedPolicyContext(request, answers, authority, additional));
                    AddNegativeTrustAnchorExtendedErrors(request, cachedResponse);
                    return Task.FromResult(cachedResponse);
                }
            }

        beforeFindClosestNameServers:

            if (findClosestNameServers)
            {
                string domain;

                if (question.Type == DnsResourceRecordType.DS)
                {
                    //find parent zone NS
                    domain = GetParentZone(question.Name);
                    if (domain is null)
                        return Task.FromResult<DnsDatagram>(null); //dont find NS for root
                }
                else
                {
                    domain = question.Name;
                }

                IReadOnlyList<DnsResourceRecord> closestAuthority = GetClosestReferralNameServers(domain, request.DnssecOk);
                if (closestAuthority is not null)
                {
                    if (!IsPolicyGenerationCompatible(request, closestAuthority))
                        return Task.FromResult<DnsDatagram>(null);

                    IReadOnlyList<DnsResourceRecord> additionalRecords = GetAdditionalRecords(closestAuthority);

                    if (!IsPolicyGenerationCompatible(request, closestAuthority, additionalRecords))
                        return Task.FromResult<DnsDatagram>(null);

                    if (HasExpiredNegativeTrustAnchor(closestAuthority))
                        return Task.FromResult<DnsDatagram>(null);

                    DnsDatagram cachedResponse = new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, CanSetAuthenticData(null, closestAuthority), request.CheckingDisabled, DnsResponseCode.NoError, request.Question, null, closestAuthority, additionalRecords);
                    cachedResponse.SetDnsCacheWriteContext(GetRetainedPolicyContext(request, closestAuthority, additionalRecords));
                    AddNegativeTrustAnchorExtendedErrors(request, cachedResponse);
                    return Task.FromResult(cachedResponse);
                }
            }

            return Task.FromResult<DnsDatagram>(null);
        }

        public void CacheResponse(DnsDatagram response, bool isDnssecBadCache = false, string zoneCut = null)
        {
            if (!response.IsResponse || response.Truncation || (response.Question.Count == 0))
                return; //ineligible response

            //Reject mixed-policy responses before stamping records. This prevents composition or
            //custom callers from laundering records produced under different trust policies.
            DnsCacheWriteContext writeContext = response.DnsCacheWriteContext;
            bool conflictingPolicyContext = false;
            bool specialRecordMissingContext = false;
            void ObserveContext(DnsCacheWriteContext context)
            {
                if ((context is null) || conflictingPolicyContext)
                    return;
                if (writeContext is null)
                    writeContext = context;
                else if (!HasSamePolicyIdentity(writeContext, context))
                    conflictingPolicyContext = true;
            }
            foreach (IReadOnlyList<DnsResourceRecord> section in new[] { response.Answer, response.Authority, response.Additional })
            {
                foreach (DnsResourceRecord record in section)
                {
                    ObserveContext(record.GetDnssecCacheMetadata().DnsCacheWriteContext);
                    if (record.RDATA is DnsSpecialCacheRecordData specialRecord)
                    {
                        if (specialRecord.DnsCacheWriteContext is null)
                            specialRecordMissingContext = true;
                        ObserveContext(specialRecord.DnsCacheWriteContext);
                        foreach (IReadOnlyList<DnsResourceRecord> nestedSection in new[] { specialRecord.OriginalAnswer, specialRecord.OriginalAuthority, specialRecord.OriginalAdditional })
                            foreach (DnsResourceRecord nestedRecord in nestedSection)
                                ObserveContext(nestedRecord.GetDnssecCacheMetadata().DnsCacheWriteContext);
                    }
                }
            }
            if (conflictingPolicyContext || (specialRecordMissingContext && (writeContext is not null)))
                return;
            if ((response.DnsCacheWriteContext is null) && (writeContext is not null))
                response.SetDnsCacheWriteContext(writeContext);

            //set expiry for all records
            {
                foreach (DnsResourceRecord record in response.Answer)
                {
                    if (response.DnsCacheWriteContext is not null)
                        record.SetDnsCacheWriteContext(response.DnsCacheWriteContext);
                    record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl, _serveStaleAnswerTtl);
                }

                foreach (DnsResourceRecord record in response.Authority)
                {
                    if (response.DnsCacheWriteContext is not null)
                        record.SetDnsCacheWriteContext(response.DnsCacheWriteContext);
                    record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl, _serveStaleAnswerTtl);
                }

                foreach (DnsResourceRecord record in response.Additional)
                {
                    if (record.Type == DnsResourceRecordType.OPT)
                        continue;

                    if (response.DnsCacheWriteContext is not null)
                        record.SetDnsCacheWriteContext(response.DnsCacheWriteContext);
                    record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl, _serveStaleAnswerTtl);
                }
            }

            //read ECS
            NetworkAddress eDnsClientSubnet = null;
            EDnsClientSubnetOptionData ecs = response.GetEDnsClientSubnetOption();
            if (ecs is not null)
                eDnsClientSubnet = new NetworkAddress(ecs.Address, Math.Min(ecs.SourcePrefixLength, ecs.ScopePrefixLength));

            if (isDnssecBadCache)
            {
                //cache as bad cache record with failure TTL
                foreach (DnsQuestionRecord question in response.Question)
                {
                    DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, question.Class, _failureRecordTtl, new DnsSpecialCacheRecordData(DnsSpecialCacheRecordType.BadCache, response));
                    record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl, _serveStaleAnswerTtl);

                    InternalCacheRecords(new DnsResourceRecord[] { record }, eDnsClientSubnet, response.Metadata);
                }

                return;
            }

            if (response.IsBlockedResponse())
            {
                uint ttl = uint.MaxValue;

                foreach (DnsResourceRecord answer in response.Answer)
                {
                    if (answer.TTL < ttl)
                        ttl = answer.TTL;
                }

                if (ttl == uint.MaxValue)
                    ttl = _negativeRecordTtl;

                //cache as negative record
                foreach (DnsQuestionRecord question in response.Question)
                {
                    DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, question.Class, ttl, new DnsSpecialCacheRecordData(DnsSpecialCacheRecordType.BlockedCache, response));
                    record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl, _serveStaleAnswerTtl);

                    InternalCacheRecords([record], eDnsClientSubnet, response.Metadata);
                }

                return;
            }

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                case DnsResponseCode.NxDomain:
                case DnsResponseCode.YXDomain:
                    //cache response after this switch
                    break;

                default:
                    //cache as failure record
                    foreach (DnsQuestionRecord question in response.Question)
                    {
                        DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, question.Class, _failureRecordTtl, new DnsSpecialCacheRecordData(DnsSpecialCacheRecordType.FailureCache, response));
                        record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl, _serveStaleAnswerTtl);

                        InternalCacheRecords(new DnsResourceRecord[] { record }, eDnsClientSubnet, response.Metadata);
                    }

                    return;
            }

            //Ordinary RRset caching cannot represent response-only resolver provenance without
            //incorrectly attaching it to an individual secure RRset. Preserve such positive
            //responses as exact composite cache entries instead.
            if ((response.Answer.Count > 0) && (response.ResponseOnlyNegativeTrustAnchors.Count > 0))
            {
                uint ttl = uint.MaxValue;
                foreach (IReadOnlyList<DnsResourceRecord> records in new[] { response.Answer, response.Authority, response.Additional })
                    foreach (DnsResourceRecord record in records)
                        if ((record.Type != DnsResourceRecordType.OPT) && (record.TTL < ttl))
                            ttl = record.TTL;
                if (ttl == uint.MaxValue)
                    ttl = _negativeRecordTtl;

                foreach (DnsQuestionRecord question in response.Question)
                {
                    DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, question.Class, ttl, new DnsSpecialCacheRecordData(DnsSpecialCacheRecordType.PositiveCache, response));
                    record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl, _serveStaleAnswerTtl);
                    InternalCacheRecords([record], eDnsClientSubnet, response.Metadata);
                }

                return;
            }

            //attach RRSIG to records
            {
                foreach (DnsResourceRecord rrsigRecord in response.Answer)
                {
                    if (rrsigRecord.Type != DnsResourceRecordType.RRSIG)
                        continue;

                    DnsRRSIGRecordData rrsig = rrsigRecord.RDATA as DnsRRSIGRecordData;

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if ((record.Type == rrsig.TypeCovered) && record.Name.Equals(rrsigRecord.Name, StringComparison.OrdinalIgnoreCase))
                        {
                            DnsResourceRecordInfo recordInfo = GetRecordInfo(record);

                            recordInfo.AddRRSIGRecord(rrsigRecord);

                            if (DnsRRSIGRecordData.IsWildcard(rrsigRecord))
                            {
                                //record is wildcard synthesized
                                //add NSEC from authority if any

                                foreach (DnsResourceRecord authority in response.Authority)
                                {
                                    switch (authority.Type)
                                    {
                                        case DnsResourceRecordType.NSEC:
                                        case DnsResourceRecordType.NSEC3:
                                            recordInfo.AddNSECRecord(authority);
                                            break;
                                    }
                                }
                            }

                            break;
                        }
                    }
                }

                foreach (DnsResourceRecord rrsigRecord in response.Authority)
                {
                    if (rrsigRecord.Type != DnsResourceRecordType.RRSIG)
                        continue;

                    DnsRRSIGRecordData rrsig = rrsigRecord.RDATA as DnsRRSIGRecordData;

                    foreach (DnsResourceRecord record in response.Authority)
                    {
                        if ((record.Type == rrsig.TypeCovered) && record.Name.Equals(rrsigRecord.Name, StringComparison.OrdinalIgnoreCase))
                        {
                            GetRecordInfo(record).AddRRSIGRecord(rrsigRecord);
                            break;
                        }
                    }
                }

                foreach (DnsResourceRecord rrsigRecord in response.Additional)
                {
                    if (rrsigRecord.Type != DnsResourceRecordType.RRSIG)
                        continue;

                    DnsRRSIGRecordData rrsig = rrsigRecord.RDATA as DnsRRSIGRecordData;

                    foreach (DnsResourceRecord record in response.Additional)
                    {
                        if ((record.Type == rrsig.TypeCovered) && record.Name.Equals(rrsigRecord.Name, StringComparison.OrdinalIgnoreCase))
                        {
                            GetRecordInfo(record).AddRRSIGRecord(rrsigRecord);
                            break;
                        }
                    }
                }
            }

            //combine all records in the response
            List<DnsResourceRecord> cachableRecords = new List<DnsResourceRecord>(response.Answer.Count);

            //get cachable answer records
            foreach (DnsQuestionRecord question in response.Question)
            {
                string qName = question.Name;

                foreach (DnsResourceRecord answer in response.Answer)
                {
                    if (answer.Name.Equals(qName, StringComparison.OrdinalIgnoreCase))
                    {
                        switch (answer.Type)
                        {
                            case DnsResourceRecordType.CNAME:
                                cachableRecords.Add(answer);

                                qName = (answer.RDATA as DnsCNAMERecordData).Domain;
                                break;

                            case DnsResourceRecordType.NS:
                                if ((question.Type == DnsResourceRecordType.NS) || (question.Type == DnsResourceRecordType.ANY))
                                {
                                    DnsResourceRecord nsRecord = answer.CloneAs(DnsResourceRecordType.CHILD_NS);
                                    cachableRecords.Add(nsRecord);

                                    //add glue from additional section
                                    string nsDomain = (nsRecord.RDATA as DnsNSRecordData).NameServer;

                                    foreach (DnsResourceRecord additional in response.Additional)
                                    {
                                        switch (additional.DnssecStatus)
                                        {
                                            case DnssecStatus.Disabled:
                                            case DnssecStatus.Secure:
                                            case DnssecStatus.Insecure:
                                            case DnssecStatus.Indeterminate:
                                                break;

                                            default:
                                                continue;
                                        }

                                        if (nsDomain.Equals(additional.Name, StringComparison.OrdinalIgnoreCase))
                                        {
                                            switch (additional.Type)
                                            {
                                                case DnsResourceRecordType.A:
                                                    if (IPAddress.IsLoopback((additional.RDATA as DnsARecordData).Address))
                                                        continue;

                                                    GetRecordInfo(nsRecord).AddGlueRecord(additional);
                                                    break;

                                                case DnsResourceRecordType.AAAA:
                                                    if (IPAddress.IsLoopback((additional.RDATA as DnsAAAARecordData).Address))
                                                        continue;

                                                    GetRecordInfo(nsRecord).AddGlueRecord(additional);
                                                    break;
                                            }
                                        }
                                    }
                                }
                                break;

                            case DnsResourceRecordType.MX:
                                if ((question.Type == DnsResourceRecordType.MX) || (question.Type == DnsResourceRecordType.ANY))
                                {
                                    cachableRecords.Add(answer);

                                    //add glue from additional section
                                    string mxExchange = (answer.RDATA as DnsMXRecordData).Exchange;

                                    foreach (DnsResourceRecord additional in response.Additional)
                                    {
                                        switch (additional.DnssecStatus)
                                        {
                                            case DnssecStatus.Disabled:
                                            case DnssecStatus.Secure:
                                            case DnssecStatus.Insecure:
                                                break;

                                            default:
                                                continue;
                                        }

                                        if (mxExchange.Equals(additional.Name, StringComparison.OrdinalIgnoreCase))
                                        {
                                            switch (additional.Type)
                                            {
                                                case DnsResourceRecordType.A:
                                                case DnsResourceRecordType.AAAA:
                                                    GetRecordInfo(answer).AddGlueRecord(additional);
                                                    break;
                                            }
                                        }
                                    }
                                }
                                break;

                            case DnsResourceRecordType.SRV:
                                if ((question.Type == DnsResourceRecordType.SRV) || (question.Type == DnsResourceRecordType.ANY))
                                {
                                    cachableRecords.Add(answer);

                                    //add glue from additional section
                                    string srvTarget = (answer.RDATA as DnsSRVRecordData).Target;

                                    foreach (DnsResourceRecord additional in response.Additional)
                                    {
                                        switch (additional.DnssecStatus)
                                        {
                                            case DnssecStatus.Disabled:
                                            case DnssecStatus.Secure:
                                            case DnssecStatus.Insecure:
                                                break;

                                            default:
                                                continue;
                                        }

                                        if (srvTarget.Equals(additional.Name, StringComparison.OrdinalIgnoreCase))
                                        {
                                            switch (additional.Type)
                                            {
                                                case DnsResourceRecordType.A:
                                                case DnsResourceRecordType.AAAA:
                                                    GetRecordInfo(answer).AddGlueRecord(additional);
                                                    break;
                                            }
                                        }
                                    }
                                }
                                break;

                            case DnsResourceRecordType.SVCB:
                            case DnsResourceRecordType.HTTPS:
                                if ((question.Type == DnsResourceRecordType.SVCB) || (question.Type == DnsResourceRecordType.HTTPS) || (question.Type == DnsResourceRecordType.ANY))
                                {
                                    cachableRecords.Add(answer);

                                    //add glue from additional section
                                    DnsSVCBRecordData svcb = answer.RDATA as DnsSVCBRecordData;
                                    string targetName = svcb.TargetName;

                                    if (svcb.SvcPriority == 0)
                                    {
                                        //Alias mode
                                        if ((targetName.Length == 0) || targetName.Equals(answer.Name, StringComparison.OrdinalIgnoreCase))
                                            break; //For AliasMode SVCB RRs, a TargetName of "." indicates that the service is not available or does not exist [draft-ietf-dnsop-svcb-https-12]
                                    }
                                    else
                                    {
                                        //Service mode
                                        if (targetName.Length == 0)
                                            targetName = answer.Name; //For ServiceMode SVCB RRs, if TargetName has the value ".", then the owner name of this record MUST be used as the effective TargetName [draft-ietf-dnsop-svcb-https-12]
                                    }

                                    foreach (DnsResourceRecord additional in response.Additional)
                                    {
                                        switch (additional.DnssecStatus)
                                        {
                                            case DnssecStatus.Disabled:
                                            case DnssecStatus.Secure:
                                            case DnssecStatus.Insecure:
                                                break;

                                            default:
                                                continue;
                                        }

                                        if (targetName.Equals(additional.Name, StringComparison.OrdinalIgnoreCase))
                                        {
                                            switch (additional.Type)
                                            {
                                                case DnsResourceRecordType.A:
                                                case DnsResourceRecordType.AAAA:
                                                case DnsResourceRecordType.SVCB:
                                                case DnsResourceRecordType.HTTPS:
                                                    GetRecordInfo(answer).AddGlueRecord(additional);
                                                    break;
                                            }
                                        }
                                    }
                                }
                                break;

                            case DnsResourceRecordType.RRSIG:
                                if ((question.Type == DnsResourceRecordType.RRSIG) || (question.Type == DnsResourceRecordType.ANY))
                                    cachableRecords.Add(answer);

                                break;

                            default:
                                if ((question.Type == answer.Type) || (question.Type == DnsResourceRecordType.ANY))
                                    cachableRecords.Add(answer);

                                break;
                        }
                    }
                    else if ((answer.Type == DnsResourceRecordType.DNAME) && qName.EndsWith("." + answer.Name, StringComparison.OrdinalIgnoreCase))
                    {
                        cachableRecords.Add(answer);
                    }
                }
            }

            //get cachable authority records
            if (response.Authority.Count > 0)
            {
                DnsResourceRecord firstAuthority = response.FindFirstAuthorityRecord();
                switch (firstAuthority.Type)
                {
                    case DnsResourceRecordType.SOA:
                        if (response.Answer.Count == 0)
                        {
                            //empty response with authority
                            foreach (DnsQuestionRecord question in response.Question)
                            {
                                DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, question.Class, Math.Min((firstAuthority.RDATA as DnsSOARecordData).Minimum, firstAuthority.OriginalTtlValue), new DnsSpecialCacheRecordData(DnsSpecialCacheRecordType.NegativeCache, response));
                                record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl, _serveStaleAnswerTtl);

                                InternalCacheRecords(new DnsResourceRecord[] { record }, eDnsClientSubnet, response.Metadata);
                            }
                        }
                        else if (zoneCut is null)
                        {
                            //answer response with authority; received from a forwarder (null zonecut)
                            DnsResourceRecord lastAnswer = response.GetLastAnswerRecord();
                            if (lastAnswer.Type == DnsResourceRecordType.CNAME)
                            {
                                string cnameDomain = (lastAnswer.RDATA as DnsCNAMERecordData).Domain;

                                if (cnameDomain.Equals(firstAuthority.Name, StringComparison.OrdinalIgnoreCase) || cnameDomain.EndsWith("." + firstAuthority.Name, StringComparison.OrdinalIgnoreCase))
                                {
                                    foreach (DnsQuestionRecord question in response.Question)
                                    {
                                        DnsResourceRecord record = new DnsResourceRecord(cnameDomain, question.Type, question.Class, Math.Min((firstAuthority.RDATA as DnsSOARecordData).Minimum, firstAuthority.OriginalTtlValue), new DnsSpecialCacheRecordData(DnsSpecialCacheRecordType.NegativeCache, response));
                                        record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl, _serveStaleAnswerTtl);

                                        InternalCacheRecords([record], eDnsClientSubnet, response.Metadata);
                                    }
                                }
                            }
                        }

                        break;

                    case DnsResourceRecordType.NS:
                        if (response.Answer.Count == 0)
                        {
                            //response is probably referral response
                            bool isReferralResponse = true;

                            if (zoneCut is null)
                                throw new InvalidOperationException("Zone cut cannot be null for caching referral response.");

                            foreach (DnsQuestionRecord question in response.Question)
                            {
                                foreach (DnsResourceRecord authority in response.Authority)
                                {
                                    if (authority.Type == DnsResourceRecordType.NS)
                                    {
                                        if (authority.Name.Equals(zoneCut, StringComparison.OrdinalIgnoreCase))
                                        {
                                            //empty response with authority name servers that match the zone cut; dont cache authority section with NS records
                                            DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, question.Class, _negativeRecordTtl, new DnsSpecialCacheRecordData(DnsSpecialCacheRecordType.NegativeCache, response.RCODE, [question], Array.Empty<DnsResourceRecord>(), Array.Empty<DnsResourceRecord>(), Array.Empty<DnsResourceRecord>(), response.EDNS, response.DnsClientExtendedErrors, response.GetResponseOnlyNegativeTrustAnchorsForRetainedSections(Array.Empty<DnsResourceRecord>(), Array.Empty<DnsResourceRecord>(), Array.Empty<DnsResourceRecord>()), response.DnsCacheWriteContext));
                                            record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl, _serveStaleAnswerTtl);

                                            InternalCacheRecords(new DnsResourceRecord[] { record }, eDnsClientSubnet, response.Metadata);
                                            isReferralResponse = false;
                                            break;
                                        }

                                        if ((zoneCut.Length > 0) && !authority.Name.EndsWith("." + zoneCut, StringComparison.OrdinalIgnoreCase))
                                        {
                                            //empty response with authority name server out of bailiwick; dont cache invalid referral response
                                            isReferralResponse = false;
                                            break;
                                        }
                                    }
                                }
                            }

                            if (isReferralResponse)
                            {
                                //cache and glue suitable NS & DS records

                                //find existing cached NS records for persistent metadata
                                DnsDatagram cachedResponse = null;

                                NameServerMetadata GetCachedMetadataFor(string zoneCut, string nsDomain)
                                {
                                    if ((cachedResponse is null) || (cachedResponse.Answer.Count == 0) || !cachedResponse.Answer[0].Name.Equals(zoneCut, StringComparison.OrdinalIgnoreCase))
                                        cachedResponse = QueryAsync(new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(zoneCut, DnsResourceRecordType.PARENT_NS, DnsClass.IN)]), true, false, false).Sync();

                                    if (cachedResponse is null)
                                        return null;

                                    foreach (DnsResourceRecord record in cachedResponse.Answer)
                                    {
                                        if (record.Type != DnsResourceRecordType.NS)
                                            continue;

                                        if (!record.Name.Equals(zoneCut, StringComparison.OrdinalIgnoreCase))
                                            continue;

                                        if (record.RDATA is DnsNSRecordData nsRecord && nsRecord.NameServer.Equals(nsDomain, StringComparison.OrdinalIgnoreCase))
                                            return nsRecord.Metadata;
                                    }

                                    return null;
                                }

                                foreach (DnsResourceRecord authority in response.Authority)
                                {
                                    switch (authority.Type)
                                    {
                                        case DnsResourceRecordType.NS:
                                            foreach (DnsQuestionRecord question in response.Question)
                                            {
                                                if (question.Name.Equals(authority.Name, StringComparison.OrdinalIgnoreCase) || question.Name.EndsWith("." + authority.Name, StringComparison.OrdinalIgnoreCase))
                                                {
                                                    cachableRecords.Add(authority);

                                                    DnsNSRecordData ns = authority.RDATA as DnsNSRecordData;
                                                    string nsDomain = ns.NameServer;

                                                    NameServerMetadata cachedMetadata = GetCachedMetadataFor(authority.Name, nsDomain);
                                                    if (cachedMetadata is not null)
                                                        ns.SetMetadata(cachedMetadata);

                                                    //add glue from additional section
                                                    foreach (DnsResourceRecord additional in response.Additional)
                                                    {
                                                        if (nsDomain.Equals(additional.Name, StringComparison.OrdinalIgnoreCase))
                                                        {
                                                            switch (additional.Type)
                                                            {
                                                                case DnsResourceRecordType.A:
                                                                    if (IPAddress.IsLoopback((additional.RDATA as DnsARecordData).Address))
                                                                        continue; //skip loopback address to avoid creating resolution loops

                                                                    GetRecordInfo(authority).AddGlueRecord(additional);
                                                                    break;

                                                                case DnsResourceRecordType.AAAA:
                                                                    if (IPAddress.IsLoopback((additional.RDATA as DnsAAAARecordData).Address))
                                                                        continue; //skip loopback address to avoid creating resolution loops

                                                                    GetRecordInfo(authority).AddGlueRecord(additional);
                                                                    break;
                                                            }
                                                        }
                                                    }

                                                    break;
                                                }
                                            }
                                            break;

                                        case DnsResourceRecordType.DS:
                                            cachableRecords.Add(authority);
                                            break;

                                        case DnsResourceRecordType.NSEC:
                                        case DnsResourceRecordType.NSEC3:
                                            foreach (DnsResourceRecord record in response.Authority)
                                            {
                                                if (record.Type == DnsResourceRecordType.NS)
                                                {
                                                    GetRecordInfo(record).AddNSECRecord(authority);
                                                    break;
                                                }
                                            }
                                            break;
                                    }
                                }
                            }
                        }

                        break;
                }
            }
            else
            {
                //no authority records
                if (response.Answer.Count == 0)
                {
                    //empty response with no authority
                    foreach (DnsQuestionRecord question in response.Question)
                    {
                        DnsResourceRecord record = new DnsResourceRecord(question.Name, question.Type, question.Class, _negativeRecordTtl, new DnsSpecialCacheRecordData(DnsSpecialCacheRecordType.NegativeCache, response));
                        record.SetExpiry(_minimumRecordTtl, _maximumRecordTtl, _serveStaleTtl, _serveStaleAnswerTtl);

                        InternalCacheRecords(new DnsResourceRecord[] { record }, eDnsClientSubnet, response.Metadata);
                    }
                }
            }

            if (cachableRecords.Count > 0)
                InternalCacheRecords(cachableRecords, eDnsClientSubnet, response.Metadata);
        }

        public virtual void RemoveExpiredRecords()
        {
            foreach (KeyValuePair<string, DnsCacheEntry> entry in _cache)
            {
                entry.Value.RemoveExpiredRecords();

                if (entry.Value.IsEmpty)
                    _cache.TryRemove(entry.Key, out _); //remove empty entry
            }
        }

        public virtual void Flush()
        {
            _cache.Clear();
        }

        #endregion

        #region properties

        public uint FailureRecordTtl
        {
            get { return _failureRecordTtl; }
            set { _failureRecordTtl = value; }
        }

        public uint NegativeRecordTtl
        {
            get { return _negativeRecordTtl; }
            set { _negativeRecordTtl = value; }
        }

        public uint MinimumRecordTtl
        {
            get { return _minimumRecordTtl; }
            set { _minimumRecordTtl = value; }
        }

        public uint MaximumRecordTtl
        {
            get { return _maximumRecordTtl; }
            set { _maximumRecordTtl = value; }
        }

        public uint ServeStaleTtl
        {
            get { return _serveStaleTtl; }
            set
            {
                if (value > SERVE_STALE_TTL_MAX)
                    throw new ArgumentOutOfRangeException(nameof(ServeStaleTtl), "Serve stale TTL cannot be higher than 7 days. Recommended value is between 1-3 days.");

                _serveStaleTtl = value;
            }
        }

        public uint ServeStaleAnswerTtl
        {
            get { return _serveStaleAnswerTtl; }
            set
            {
                if (value > SERVE_STALE_ANSWER_TTL_MAX)
                    throw new ArgumentOutOfRangeException(nameof(ServeStaleAnswerTtl), "Serve stale answer TTL cannot be higher than 5 minutes. Recommended value is 30 seconds.");

                _serveStaleAnswerTtl = value;
            }
        }

        #endregion

        public enum DnsSpecialCacheRecordType : byte
        {
            Unknown = 0,
            NegativeCache = 1,
            FailureCache = 2,
            BadCache = 3,
            BlockedCache = 4,
            PositiveCache = 5
        }

        public class DnsSpecialCacheRecordData : DnsResourceRecordData
        {
            #region variables

            readonly DnsSpecialCacheRecordType _type;
            readonly DnsResponseCode _rcode;
            readonly IReadOnlyList<DnsResourceRecord> _answer;
            readonly IReadOnlyList<DnsResourceRecord> _authority;
            readonly IReadOnlyList<DnsResourceRecord> _additional;

            readonly List<EDnsOption> _ednsOptions;
            IReadOnlyList<NegativeTrustAnchorInfo> _appliedNegativeTrustAnchors;
            readonly DnsCacheWriteContext _dnsCacheWriteContext;

            readonly IReadOnlyList<DnsResourceRecord> _noDnssecAnswer;
            readonly IReadOnlyList<DnsResourceRecord> _noDnssecAuthority;

            #endregion

            #region constructor

            public DnsSpecialCacheRecordData(DnsSpecialCacheRecordType type, DnsDatagram response)
                : this(type, response.RCODE, response.Question, response.Answer, response.Authority, response.Additional, response.EDNS, response.DnsClientExtendedErrors, response.ResponseOnlyNegativeTrustAnchors, response.DnsCacheWriteContext)
            { }

            public DnsSpecialCacheRecordData(DnsSpecialCacheRecordType type, DnsResponseCode rcode, IReadOnlyList<DnsQuestionRecord> question, IReadOnlyList<DnsResourceRecord> answer, IReadOnlyList<DnsResourceRecord> authority, IReadOnlyList<DnsResourceRecord> additional, DnsDatagramEdns edns, IReadOnlyList<EDnsExtendedDnsErrorOptionData> dnsClientExtendedErrors)
                : this(type, rcode, question, answer, authority, additional, edns, dnsClientExtendedErrors, null)
            { }

            public DnsSpecialCacheRecordData(DnsSpecialCacheRecordType type, DnsResponseCode rcode, IReadOnlyList<DnsQuestionRecord> question, IReadOnlyList<DnsResourceRecord> answer, IReadOnlyList<DnsResourceRecord> authority, IReadOnlyList<DnsResourceRecord> additional, DnsDatagramEdns edns, IReadOnlyList<EDnsExtendedDnsErrorOptionData> dnsClientExtendedErrors, IReadOnlyList<NegativeTrustAnchorInfo> appliedNegativeTrustAnchors, DnsCacheWriteContext dnsCacheWriteContext = null)
            {
                _type = type;
                _rcode = rcode;
                _answer = answer;
                _authority = authority;
                _additional = additional;
                _dnsCacheWriteContext = dnsCacheWriteContext;
                if ((appliedNegativeTrustAnchors is not null) && (appliedNegativeTrustAnchors.Count > 0))
                {
                    Dictionary<string, NegativeTrustAnchorInfo> anchors = new Dictionary<string, NegativeTrustAnchorInfo>(StringComparer.OrdinalIgnoreCase);
                    foreach (NegativeTrustAnchorInfo anchor in appliedNegativeTrustAnchors)
                    {
                        if (anchor is null)
                            continue;
                        if (anchors.TryGetValue(anchor.Name, out NegativeTrustAnchorInfo existing))
                            anchors[anchor.Name] = existing.MergeMostRestrictive(anchor);
                        else
                            anchors.Add(anchor.Name, anchor);
                    }
                    _appliedNegativeTrustAnchors = Array.AsReadOnly(anchors.Values.OrderBy(anchor => anchor.Name, StringComparer.OrdinalIgnoreCase).ToArray());
                }

                //prepare EDNS options
                {
                    List<EDnsOption> ednsOptions = new List<EDnsOption>();

                    //copy extended dns errors from response
                    if (edns is not null)
                    {
                        foreach (EDnsOption option in edns.Options)
                        {
                            if (option.Code == EDnsOptionCode.EXTENDED_DNS_ERROR)
                                ednsOptions.Add(option);
                        }
                    }

                    //copy extended dns errors generated by dns client
                    foreach (EDnsExtendedDnsErrorOptionData dnsError in dnsClientExtendedErrors)
                    {
                        EDnsOption ednsOption = new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, dnsError);

                        if (!ednsOptions.Contains(ednsOption))
                            ednsOptions.Add(ednsOption);
                    }

                    //add additional extended dns error
                    switch (rcode)
                    {
                        case DnsResponseCode.NoError:
                        case DnsResponseCode.NxDomain:
                        case DnsResponseCode.YXDomain:
                            break;

                        default:
                            ednsOptions.Add(new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.CachedError, question.Count > 0 ? question[0].ToString() : null)));
                            break;
                    }

                    _ednsOptions = ednsOptions;
                }

                //get answer and authority section with no dnssec records
                _noDnssecAnswer = FilterDnssecAnswerRecords(_answer);
                _noDnssecAuthority = FilterDnssecAuthorityRecords(_authority);

                //remove OPT additional
                if ((_additional.Count == 1) && (_additional[0].Type == DnsResourceRecordType.OPT))
                {
                    _additional = Array.Empty<DnsResourceRecord>();
                }
                else if (_additional.Count > 0)
                {
                    bool foundOpt = false;

                    foreach (DnsResourceRecord record in _additional)
                    {
                        if (record.Type == DnsResourceRecordType.OPT)
                        {
                            foundOpt = true;
                            break;
                        }
                    }

                    if (foundOpt)
                    {
                        List<DnsResourceRecord> newAdditional = new List<DnsResourceRecord>(_additional.Count - 1);

                        foreach (DnsResourceRecord record2 in _additional)
                        {
                            if (record2.Type == DnsResourceRecordType.OPT)
                                continue;

                            newAdditional.Add(record2);
                        }

                        _additional = newAdditional;
                    }
                }
            }

            private DnsSpecialCacheRecordData(DnsSpecialCacheRecordType type, DnsResponseCode rcode, IReadOnlyList<DnsResourceRecord> answer, IReadOnlyList<DnsResourceRecord> authority, IReadOnlyList<DnsResourceRecord> additional, List<EDnsOption> ednsOptions, IReadOnlyList<NegativeTrustAnchorInfo> appliedNegativeTrustAnchors, DnsCacheWriteContext dnsCacheWriteContext)
            {
                _type = type;
                _rcode = rcode;
                _answer = answer;
                _authority = authority;
                _additional = additional;
                _ednsOptions = ednsOptions;
                _appliedNegativeTrustAnchors = appliedNegativeTrustAnchors;
                _dnsCacheWriteContext = dnsCacheWriteContext;

                //get answer and authority section with no dnssec records
                _noDnssecAnswer = FilterDnssecAnswerRecords(_answer);
                _noDnssecAuthority = FilterDnssecAuthorityRecords(_authority);
            }

            #endregion

            #region static

            public static DnsSpecialCacheRecordData ReadCacheRecordFrom(BinaryReader bR, Action<DnsResourceRecord> readTagInfo)
            {
                byte version = bR.ReadByte();
                switch (version)
                {
                    case 1:
                    case 2:
                    case 3:
                    case 4:
                    case 5:
                    case 6:
                        DnsSpecialCacheRecordType type = (DnsSpecialCacheRecordType)bR.ReadByte();
                        DnsResponseCode rcode = (DnsResponseCode)bR.ReadUInt16();
                        IReadOnlyList<DnsResourceRecord> answer = ReadCacheRecordsFrom(bR, readTagInfo);
                        IReadOnlyList<DnsResourceRecord> authority = ReadCacheRecordsFrom(bR, readTagInfo);
                        IReadOnlyList<DnsResourceRecord> additional = ReadCacheRecordsFrom(bR, readTagInfo);

                        List<EDnsOption> ednsOptions;
                        {
                            int count = bR.ReadByte();
                            ednsOptions = new List<EDnsOption>(count);

                            for (int i = 0; i < count; i++)
                                ednsOptions.Add(new EDnsOption(bR.BaseStream));
                        }

                        if (version == 1)
                            _ = ReadCacheRecordsFrom(bR, readTagInfo); //read obsolete field

                        NegativeTrustAnchorInfo[] appliedNegativeTrustAnchors = null;
                        if (version >= 3)
                        {
                            int anchorCount = bR.ReadByte();
                            if (anchorCount > 0)
                            {
                                appliedNegativeTrustAnchors = new NegativeTrustAnchorInfo[anchorCount];
                                for (int i = 0; i < anchorCount; i++)
                                    appliedNegativeTrustAnchors[i] = new NegativeTrustAnchorInfo(bR.ReadString(), new DateTimeOffset(bR.ReadInt64(), TimeSpan.Zero));
                            }
                        }

                        DnsCacheWriteContext dnsCacheWriteContext = null;
                        if ((version >= 4) && bR.ReadBoolean())
                        {
                            long generation = bR.ReadInt64();
                            DateTimeOffset capturedOnUtc = new DateTimeOffset(bR.ReadInt64(), TimeSpan.Zero);
                            Guid policyScopeId = version >= 5 ? new Guid(bR.ReadBytes(16)) : Guid.Empty;
                            Guid policyRevisionId = version >= 6 ? new Guid(bR.ReadBytes(16)) : Guid.Empty;
                            dnsCacheWriteContext = new DnsCacheWriteContext(generation, capturedOnUtc, policyScopeId, policyRevisionId);
                        }

                        return new DnsSpecialCacheRecordData(type, rcode, answer, authority, additional, ednsOptions, appliedNegativeTrustAnchors is null ? null : Array.AsReadOnly(appliedNegativeTrustAnchors), dnsCacheWriteContext);

                    default:
                        throw new InvalidDataException("DnsCache.DnsSpecialCacheRecordData format version not supported.");
                }
            }

            public static IReadOnlyList<DnsResourceRecord> FilterDnssecAnswerRecords(IReadOnlyList<DnsResourceRecord> records)
            {
                foreach (DnsResourceRecord record1 in records)
                {
                    switch (record1.Type)
                    {
                        case DnsResourceRecordType.RRSIG:
                            List<DnsResourceRecord> noDnssecRecords = new List<DnsResourceRecord>();

                            foreach (DnsResourceRecord record2 in records)
                            {
                                switch (record2.Type)
                                {
                                    case DnsResourceRecordType.RRSIG:
                                        break;

                                    default:
                                        noDnssecRecords.Add(record2);
                                        break;
                                }
                            }

                            return noDnssecRecords;
                    }
                }

                return records;
            }

            public static IReadOnlyList<DnsResourceRecord> FilterDnssecAuthorityRecords(IReadOnlyList<DnsResourceRecord> records)
            {
                foreach (DnsResourceRecord record1 in records)
                {
                    switch (record1.Type)
                    {
                        case DnsResourceRecordType.DS:
                        case DnsResourceRecordType.RRSIG:
                        case DnsResourceRecordType.NSEC:
                        case DnsResourceRecordType.NSEC3:
                            List<DnsResourceRecord> noDnssecRecords = new List<DnsResourceRecord>();

                            foreach (DnsResourceRecord record2 in records)
                            {
                                switch (record2.Type)
                                {
                                    case DnsResourceRecordType.DS:
                                    case DnsResourceRecordType.RRSIG:
                                    case DnsResourceRecordType.NSEC:
                                    case DnsResourceRecordType.NSEC3:
                                        break;

                                    default:
                                        noDnssecRecords.Add(record2);
                                        break;
                                }
                            }

                            return noDnssecRecords;
                    }
                }

                return records;
            }

            #endregion

            #region protected

            protected override void ReadRecordData(Stream s)
            {
                throw new InvalidOperationException();
            }

            protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
            {
                throw new InvalidOperationException();
            }

            #endregion

            #region private

            private static DnsResourceRecord[] ReadCacheRecordsFrom(BinaryReader bR, Action<DnsResourceRecord> readTagInfo)
            {
                int count = bR.ReadByte();
                if (count == 0)
                    return Array.Empty<DnsResourceRecord>();

                DnsResourceRecord[] records = new DnsResourceRecord[count];

                for (int i = 0; i < count; i++)
                    records[i] = DnsResourceRecord.ReadCacheRecordFrom(bR, readTagInfo);

                return records;
            }

            private static void WriteCacheRecordsTo(IReadOnlyList<DnsResourceRecord> records, BinaryWriter bW, Action writeTagInfo)
            {
                if (records is null)
                {
                    bW.Write((byte)0);
                }
                else
                {
                    bW.Write(Convert.ToByte(records.Count));

                    foreach (DnsResourceRecord record in records)
                        record.WriteCacheRecordTo(bW, writeTagInfo);
                }
            }

            #endregion

            #region internal

            internal override string ToZoneFileEntry(string originDomain = null)
            {
                throw new InvalidOperationException();
            }

            #endregion

            #region public

            public void WriteCacheRecordTo(BinaryWriter bW, Action writeTagInfo)
            {
                bW.Write((byte)6); //version

                bW.Write((byte)_type);
                bW.Write((ushort)_rcode);
                WriteCacheRecordsTo(_answer, bW, writeTagInfo);
                WriteCacheRecordsTo(_authority, bW, writeTagInfo);
                WriteCacheRecordsTo(_additional, bW, writeTagInfo);

                if (_ednsOptions is null)
                {
                    bW.Write((byte)0);
                }
                else
                {
                    int count = _ednsOptions.Count;
                    if (count > byte.MaxValue)
                        count = byte.MaxValue; //limit edns options to 255

                    bW.Write((byte)count);

                    for (int i = 0; i < count; i++)
                        _ednsOptions[i].WriteTo(bW.BaseStream);
                }

                int anchorCount = _appliedNegativeTrustAnchors?.Count ?? 0;
                if (anchorCount > byte.MaxValue)
                    anchorCount = byte.MaxValue;
                bW.Write(Convert.ToByte(anchorCount));
                for (int i = 0; i < anchorCount; i++)
                {
                    bW.Write(_appliedNegativeTrustAnchors[i].Name);
                    bW.Write(_appliedNegativeTrustAnchors[i].ExpiresOnUtc.UtcDateTime.Ticks);
                }

                bW.Write(_dnsCacheWriteContext is not null);
                if (_dnsCacheWriteContext is not null)
                {
                    bW.Write(_dnsCacheWriteContext.DnssecPolicyGeneration);
                    bW.Write(_dnsCacheWriteContext.PolicyCapturedOnUtc.UtcDateTime.Ticks);
                    bW.Write(_dnsCacheWriteContext.PolicyScopeId.ToByteArray());
                    bW.Write(_dnsCacheWriteContext.PolicyRevisionId.ToByteArray());
                }
            }

            public void CopyExtendedDnsErrorsFrom(DnsSpecialCacheRecordData other)
            {
                foreach (EDnsOption option in other._ednsOptions)
                {
                    if (option.Code == EDnsOptionCode.EXTENDED_DNS_ERROR)
                    {
                        if (!_ednsOptions.Contains(option))
                            _ednsOptions.Add(option);
                    }
                }
            }

            public override bool Equals(object obj)
            {
                if (obj is null)
                    return false;

                if (ReferenceEquals(this, obj))
                    return true;

                if (obj is DnsSpecialCacheRecordData other)
                {
                    if (_type != other._type)
                        return false;

                    if (_rcode != other._rcode)
                        return false;

                    if (!_answer.Equals(other._answer))
                        return false;

                    if (!_authority.Equals(other._authority))
                        return false;

                    if (!_additional.Equals(other._additional))
                        return false;

                    if (_dnsCacheWriteContext != other._dnsCacheWriteContext)
                        return false;

                    int anchorCount = _appliedNegativeTrustAnchors?.Count ?? 0;
                    if (anchorCount != (other._appliedNegativeTrustAnchors?.Count ?? 0))
                        return false;
                    foreach (NegativeTrustAnchorInfo anchor in _appliedNegativeTrustAnchors ?? Array.Empty<NegativeTrustAnchorInfo>())
                    {
                        bool found = false;
                        foreach (NegativeTrustAnchorInfo otherAnchor in other._appliedNegativeTrustAnchors)
                        {
                            if (anchor.Name.Equals(otherAnchor.Name, StringComparison.OrdinalIgnoreCase) && (anchor.ExpiresOnUtc == otherAnchor.ExpiresOnUtc))
                            {
                                found = true;
                                break;
                            }
                        }
                        if (!found)
                            return false;
                    }

                    return true;
                }

                return false;
            }

            public override int GetHashCode()
            {
                HashCode hash = new HashCode();
                hash.Add(_type);
                hash.Add(_rcode);
                hash.Add(_answer.GetArrayHashCode());
                hash.Add(_authority.GetArrayHashCode());
                hash.Add(_additional.GetArrayHashCode());
                hash.Add(_dnsCacheWriteContext);
                int anchorsHash = 0;
                if (_appliedNegativeTrustAnchors is not null)
                    foreach (NegativeTrustAnchorInfo anchor in _appliedNegativeTrustAnchors)
                        anchorsHash ^= HashCode.Combine(StringComparer.OrdinalIgnoreCase.GetHashCode(anchor.Name), anchor.ExpiresOnUtc);
                hash.Add(anchorsHash);
                return hash.ToHashCode();
            }

            public override string ToString()
            {
                string value = _type.ToString() + ": " + _rcode.ToString();

                if (_ednsOptions is not null)
                {
                    string extendedErrors = null;

                    foreach (EDnsOption option in _ednsOptions)
                    {
                        if (option.Code == EDnsOptionCode.EXTENDED_DNS_ERROR)
                        {
                            EDnsExtendedDnsErrorOptionData dnsError = option.Data as EDnsExtendedDnsErrorOptionData;
                            if (dnsError.InfoCode == EDnsExtendedDnsErrorCode.CachedError)
                                continue;

                            if (extendedErrors is null)
                                extendedErrors = dnsError.InfoCode.ToString() + (string.IsNullOrEmpty(dnsError.ExtraText) ? "" : ": " + dnsError.ExtraText);
                            else
                                extendedErrors += ", " + dnsError.InfoCode.ToString() + (string.IsNullOrEmpty(dnsError.ExtraText) ? "" : ": " + dnsError.ExtraText);
                        }
                    }

                    if (extendedErrors is not null)
                        value += "; " + extendedErrors;
                }

                if (_authority is not null)
                {
                    string authority = null;

                    foreach (DnsResourceRecord record in _authority)
                    {
                        if (authority is null)
                            authority = record.ToString();
                        else
                            authority += ", " + record.ToString();
                    }

                    if (authority is not null)
                        value += "; " + authority;
                }

                return value;
            }

            public override void SerializeTo(Utf8JsonWriter jsonWriter)
            {
                throw new InvalidOperationException();
            }

            #endregion

            #region properties

            public DnsSpecialCacheRecordType Type
            { get { return _type; } }

            public bool IsFailureOrBadCache
            {
                get
                {
                    switch (_type)
                    {
                        case DnsSpecialCacheRecordType.FailureCache:
                        case DnsSpecialCacheRecordType.BadCache:
                            return true;

                        default:
                            return false;
                    }
                }
            }

            public DnsResponseCode RCODE
            {
                get
                {
                    switch (_type)
                    {
                        case DnsSpecialCacheRecordType.FailureCache:
                        case DnsSpecialCacheRecordType.BadCache:
                            return DnsResponseCode.ServerFailure;

                        default:
                            switch (_rcode)
                            {
                                case DnsResponseCode.NoError:
                                case DnsResponseCode.NxDomain:
                                case DnsResponseCode.YXDomain:
                                    return _rcode;

                                default:
                                    return DnsResponseCode.ServerFailure;
                            }
                    }
                }
            }

            public DnsResponseCode OriginalRCODE
            { get { return _rcode; } }

            public IReadOnlyList<DnsResourceRecord> OriginalAnswer
            { get { return _answer; } }

            public IReadOnlyList<DnsResourceRecord> OriginalNoDnssecAnswer
            { get { return _noDnssecAnswer; } }

            public IReadOnlyList<DnsResourceRecord> Answer
            {
                get
                {
                    if ((_type == DnsSpecialCacheRecordType.BlockedCache) || (_type == DnsSpecialCacheRecordType.PositiveCache))
                        return _answer;

                    return [];
                }
            }

            public IReadOnlyList<DnsResourceRecord> NoDnssecAnswer
            {
                get
                {
                    if ((_type == DnsSpecialCacheRecordType.BlockedCache) || (_type == DnsSpecialCacheRecordType.PositiveCache))
                        return _noDnssecAnswer;

                    return [];
                }
            }

            public IReadOnlyList<DnsResourceRecord> OriginalAuthority
            { get { return _authority; } }

            public IReadOnlyList<DnsResourceRecord> OriginalNoDnssecAuthority
            { get { return _noDnssecAuthority; } }

            public IReadOnlyList<DnsResourceRecord> Authority
            {
                get
                {
                    if (_type == DnsSpecialCacheRecordType.BadCache)
                        return [];

                    return _authority;
                }
            }

            public IReadOnlyList<DnsResourceRecord> NoDnssecAuthority
            {
                get
                {
                    if (_type == DnsSpecialCacheRecordType.BadCache)
                        return [];

                    return _noDnssecAuthority;
                }
            }

            public IReadOnlyList<DnsResourceRecord> OriginalAdditional
            { get { return _additional; } }

            public IReadOnlyList<EDnsOption> EDnsOptions
            { get { return _ednsOptions; } }

            public IReadOnlyList<NegativeTrustAnchorInfo> AppliedNegativeTrustAnchors
            { get { return _appliedNegativeTrustAnchors ?? Array.Empty<NegativeTrustAnchorInfo>(); } }

            public DnsCacheWriteContext DnsCacheWriteContext
            { get { return _dnsCacheWriteContext; } }

            public override int UncompressedLength
            { get { throw new InvalidOperationException(); } }

            #endregion
        }

        class DnsCacheEntry
        {
            #region variables

            readonly ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> _entries;

            #endregion

            #region constructor

            public DnsCacheEntry(int capacity)
            {
                _entries = new ConcurrentDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>>(1, capacity);
            }

            #endregion

            #region static

            public static DnsCacheEntry GetRootCacheEntry()
            {
                List<DnsResourceRecord> rrset = new List<DnsResourceRecord>(13);

                foreach (NameServerAddress ipv4Hint in DnsClient.IPv4RootHints)
                {
                    string nsDomain = ipv4Hint.Host;

                    DnsResourceRecord nsRecord = new DnsResourceRecord("", DnsResourceRecordType.NS, DnsClass.IN, 518400, new DnsNSRecordData(nsDomain));
                    DnsResourceRecordInfo nsRecordInfo = GetRecordInfo(nsRecord);

                    DnsResourceRecord ipv4Glue = new DnsResourceRecord(nsDomain, DnsResourceRecordType.A, DnsClass.IN, 518400, new DnsARecordData(ipv4Hint.IPEndPoint.Address));
                    nsRecordInfo.AddGlueRecord(ipv4Glue);

                    foreach (NameServerAddress ipv6Hint in DnsClient.IPv6RootHints)
                    {
                        if (ipv6Hint.Host.Equals(nsDomain, StringComparison.OrdinalIgnoreCase))
                        {
                            DnsResourceRecord ipv6Glue = new DnsResourceRecord(nsDomain, DnsResourceRecordType.AAAA, DnsClass.IN, 518400, new DnsAAAARecordData(ipv6Hint.IPEndPoint.Address));
                            nsRecordInfo.AddGlueRecord(ipv6Glue);
                            break;
                        }
                    }

                    rrset.Add(nsRecord);
                }

                DnsCacheEntry entry = new DnsCacheEntry(1);
                entry._entries[DnsResourceRecordType.NS] = rrset;

                return entry;
            }

            #endregion

            #region private

            private static IReadOnlyList<DnsResourceRecord> ValidateRRSet(IReadOnlyList<DnsResourceRecord> records, bool skipSpecialCacheRecord)
            {
                foreach (DnsResourceRecord record in records)
                {
                    if (record.IsStale)
                        return []; //RR Set is stale

                    if ((record.AppliedNegativeTrustAnchor is not null) && (record.AppliedNegativeTrustAnchor.ExpiresOnUtc <= DateTimeOffset.UtcNow))
                        return []; //policy used to accept this RRSet has expired

                    if ((record.RDATA is DnsSpecialCacheRecordData specialRecord) && HasExpiredNegativeTrustAnchor(specialRecord))
                        return []; //policy used to accept this special response has expired

                    if (skipSpecialCacheRecord && (record.RDATA is DnsSpecialCacheRecordData))
                        return []; //RR Set is special cache record
                }

                if (records.Count > 1)
                {
                    switch (records[0].Type)
                    {
                        case DnsResourceRecordType.A:
                        case DnsResourceRecordType.AAAA:
                            List<DnsResourceRecord> newRecords = new List<DnsResourceRecord>(records);
                            newRecords.Shuffle(); //shuffle records to allow load balancing
                            return newRecords;
                    }
                }

                return records;
            }

            #endregion

            #region public

            public void SetRecords(IReadOnlyList<DnsResourceRecord> records)
            {
                if (records.Count == 0)
                    return;

                DnsResourceRecord firstRecord = records[0];
                DnsResourceRecordType type = firstRecord.Type;

                if (firstRecord.RDATA is DnsSpecialCacheRecordData splRecord)
                {
                    if (splRecord.Type == DnsSpecialCacheRecordType.PositiveCache)
                    {
                        //A composite positive response replaces every RRset representation
                        //which the normal lookup rules could use for the same question.
                        _entries.TryRemove(DnsResourceRecordType.CNAME, out _);
                        if (type == DnsResourceRecordType.ANY)
                            _entries.Clear();
                        else if (type == DnsResourceRecordType.NS)
                            _entries.TryRemove(DnsResourceRecordType.CHILD_NS, out _);
                        else if (type == DnsResourceRecordType.PARENT_NS)
                            _entries.TryRemove(DnsResourceRecordType.NS, out _);
                    }

                    if (splRecord.IsFailureOrBadCache)
                    {
                        //call trying to cache failure record
                        if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords) && (existingRecords.Count > 0) && !DnsResourceRecord.IsRRSetStale(existingRecords))
                        {
                            if ((existingRecords[0].RDATA is not DnsSpecialCacheRecordData existingSplRecord) || !existingSplRecord.IsFailureOrBadCache)
                                return; //skip to avoid overwriting a useful record with a failure record

                            //copy extended errors from existing spl record
                            splRecord.CopyExtendedDnsErrorsFrom(existingSplRecord);
                        }
                    }

                    if (type == DnsResourceRecordType.NS)
                    {
                        //remove expired CHILD_NS entry only when parent side NS record being cached is a special cache record
                        if (_entries.TryGetValue(DnsResourceRecordType.CHILD_NS, out IReadOnlyList<DnsResourceRecord> existingChildNSRecords))
                        {
                            if ((existingChildNSRecords.Count > 0) && (existingChildNSRecords[0].RDATA is DnsNSRecordData) && existingChildNSRecords[0].IsStale)
                            {
                                //delete CHILD_NS entry only when it contains expired records and not special cache records
                                _entries.TryRemove(DnsResourceRecordType.CHILD_NS, out _);
                            }
                        }
                    }
                }
                else if (type == DnsResourceRecordType.CHILD_NS)
                {
                    //convert back RRSet to correct type
                    DnsResourceRecord[] newRecords = new DnsResourceRecord[records.Count];

                    for (int i = 0; i < records.Count; i++)
                    {
                        DnsResourceRecord record = records[i];

                        if (record.Type == DnsResourceRecordType.CHILD_NS)
                            record = record.CloneAs(DnsResourceRecordType.NS);

                        newRecords[i] = record;
                    }

                    records = newRecords;
                }

                //Remove composite responses superseded by a newly accepted ordinary RRset.
                //Failure and bad-cache records return above when useful data must be retained.
                if (firstRecord.RDATA is not DnsSpecialCacheRecordData)
                {
                    RemovePositiveCache(DnsResourceRecordType.ANY);
                    switch (type)
                    {
                        case DnsResourceRecordType.CNAME:
                            foreach (DnsResourceRecordType existingType in _entries.Keys)
                                RemovePositiveCache(existingType);
                            break;
                        case DnsResourceRecordType.CHILD_NS:
                            RemovePositiveCache(DnsResourceRecordType.NS);
                            break;
                        case DnsResourceRecordType.NS:
                            RemovePositiveCache(DnsResourceRecordType.PARENT_NS);
                            break;
                        default:
                            RemovePositiveCache(type);
                            break;
                    }
                }

                if (type == DnsResourceRecordType.CNAME)
                {
                    foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
                    {
                        if ((entry.Value.Count > 0) &&
                            (entry.Value[0].RDATA is DnsSpecialCacheRecordData existingSpecialRecord) &&
                            (existingSpecialRecord.Type == DnsSpecialCacheRecordType.PositiveCache))
                        {
                            _entries.TryRemove(entry.Key, out _);
                        }
                    }
                }

                _entries[type] = records;
            }

            public IReadOnlyList<DnsResourceRecord> QueryRecords(DnsResourceRecordType type, bool skipSpecialCacheRecord)
            {
                switch (type)
                {
                    case DnsResourceRecordType.DS:
                        {
                            //since some zones have CNAME at apex!
                            if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
                                return ValidateRRSet(existingRecords, skipSpecialCacheRecord);
                        }
                        break;

                    case DnsResourceRecordType.SOA:
                    case DnsResourceRecordType.DNSKEY:
                        {
                            //since some zones have CNAME at apex!
                            if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
                                return ValidateRRSet(existingRecords, skipSpecialCacheRecord);

                            if (_entries.TryGetValue(DnsResourceRecordType.CNAME, out IReadOnlyList<DnsResourceRecord> existingCNAMERecords))
                            {
                                IReadOnlyList<DnsResourceRecord> rrset = ValidateRRSet(existingCNAMERecords, skipSpecialCacheRecord);
                                if (rrset.Count > 0)
                                {
                                    if ((type == DnsResourceRecordType.CNAME) || (rrset[0].RDATA is DnsCNAMERecordData))
                                        return rrset;
                                }
                            }
                        }
                        break;

                    case DnsResourceRecordType.ANY:
                        List<DnsResourceRecord> anyRecords = new List<DnsResourceRecord>();

                        foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
                        {
                            switch (entry.Key)
                            {
                                case DnsResourceRecordType.DS:
                                case DnsResourceRecordType.NS: //parent side NS
                                    continue;
                            }

                            anyRecords.AddRange(ValidateRRSet(entry.Value, true));
                        }

                        return anyRecords;

                    default:
                        {
                            if (_entries.TryGetValue(DnsResourceRecordType.CNAME, out IReadOnlyList<DnsResourceRecord> existingCNAMERecords))
                            {
                                IReadOnlyList<DnsResourceRecord> rrset = ValidateRRSet(existingCNAMERecords, skipSpecialCacheRecord);
                                if (rrset.Count > 0)
                                {
                                    if ((type == DnsResourceRecordType.CNAME) || (rrset[0].RDATA is DnsCNAMERecordData))
                                        return rrset;
                                }
                            }

                            switch (type)
                            {
                                case DnsResourceRecordType.NS: //normal NS query
                                    type = DnsResourceRecordType.CHILD_NS; //answer with child NS
                                    break;

                                case DnsResourceRecordType.PARENT_NS: //explicit parent side NS query
                                    type = DnsResourceRecordType.NS; //answer with parent NS
                                    break;
                            }

                            if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
                                return ValidateRRSet(existingRecords, skipSpecialCacheRecord);

                            if (type == DnsResourceRecordType.CHILD_NS)
                            {
                                //child NS does not exist so check for parent side NS if that too does not exist
                                if (_entries.TryGetValue(DnsResourceRecordType.NS, out IReadOnlyList<DnsResourceRecord> existingParentNSRecords))
                                {
                                    if ((existingParentNSRecords.Count > 0) && (existingParentNSRecords[0].RDATA is DnsSpecialCacheRecordData))
                                        return ValidateRRSet(existingParentNSRecords, skipSpecialCacheRecord); //parent side NS record does not exist so use this to answer for child NS queries
                                }
                            }
                        }
                        break;
                }

                return [];
            }

            public IReadOnlyList<DnsResourceRecord> QueryPositiveCache(DnsResourceRecordType type)
            {
                if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> records) &&
                    (records.Count > 0) &&
                    (records[0].RDATA is DnsSpecialCacheRecordData specialRecord) &&
                    (specialRecord.Type == DnsSpecialCacheRecordType.PositiveCache))
                {
                    return ValidateRRSet(records, false);
                }

                return [];
            }

            private void RemovePositiveCache(DnsResourceRecordType type)
            {
                if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> records) &&
                    (records.Count > 0) &&
                    (records[0].RDATA is DnsSpecialCacheRecordData specialRecord) &&
                    (specialRecord.Type == DnsSpecialCacheRecordType.PositiveCache))
                {
                    _entries.TryRemove(type, out _);
                }
            }

            public void RemoveExpiredRecords()
            {
                foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
                {
                    if (DnsResourceRecord.IsRRSetStale(entry.Value) || HasExpiredNegativeTrustAnchor(entry.Value))
                        _entries.TryRemove(entry.Key, out _); //RR Set or accepting NTA is expired
                }
            }

            #endregion

            #region properties

            public bool IsEmpty
            { get { return _entries.IsEmpty; } }

            #endregion
        }

        protected class DnsResourceRecordInfo
        {
            #region variables

            List<DnsResourceRecord> _glueRecords;
            List<DnsResourceRecord> _rrsigRecords;
            List<DnsResourceRecord> _nsecRecords;

            #endregion

            #region internal

            internal void AddGlueRecord(DnsResourceRecord glueRecord)
            {
                if (_glueRecords is null)
                    _glueRecords = new List<DnsResourceRecord>(2);

                _glueRecords.Add(glueRecord);
            }

            internal void AddRRSIGRecord(DnsResourceRecord rrsigRecord)
            {
                if (_rrsigRecords is null)
                    _rrsigRecords = new List<DnsResourceRecord>(1);

                _rrsigRecords.Add(rrsigRecord);
            }

            internal void AddNSECRecord(DnsResourceRecord nsecRecord)
            {
                if (_nsecRecords is null)
                    _nsecRecords = new List<DnsResourceRecord>(2);

                _nsecRecords.Add(nsecRecord);
            }

            #endregion

            #region properties

            public IReadOnlyList<DnsResourceRecord> GlueRecords
            { get { return _glueRecords; } }

            public IReadOnlyList<DnsResourceRecord> RRSIGRecords
            { get { return _rrsigRecords; } }

            public IReadOnlyList<DnsResourceRecord> NSECRecords
            { get { return _nsecRecords; } }

            #endregion
        }
    }
}
