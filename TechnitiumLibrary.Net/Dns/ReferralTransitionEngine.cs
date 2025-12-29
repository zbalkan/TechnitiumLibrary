using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Net.Sockets;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using System.Net;

namespace TechnitiumLibrary.Net.Dns
{
    internal sealed class ReferralTransitionEngine
    {
        private readonly QueryContext _ctx;
        private readonly IDnsCache _cache;
        private readonly bool _preferIPv6;
        private readonly bool _asyncNsResolution;
        private readonly Dictionary<string, object>? _asyncTasks;

        public ReferralTransitionEngine(
            QueryContext ctx,
            IDnsCache cache,
            bool preferIPv6,
            bool asyncNsResolution,
            Dictionary<string, object>? asyncTasks)
        {
            _ctx = ctx;
            _cache = cache;
            _preferIPv6 = preferIPv6;
            _asyncNsResolution = asyncNsResolution;
            _asyncTasks = asyncTasks;
        }

        /// <summary>
        /// Applies referral transition:
        /// - Extracts next NS set
        /// - Advances zone cut
        /// - Carries DNSSEC trust state
        /// - Adds async NS resolution tasks (if enabled)
        /// </summary>
        public async Task MoveToNextZoneAsync(
            ResolverDecision decision,
            List<EDnsExtendedDnsErrorOptionData> extendedErrors)
        {
            var response = decision.Response!;
            var firstAuthority = response.FindFirstAuthorityRecord();
            var nextZoneCut = firstAuthority.Name;

            //
            // ---- Extract NS set from referral ----
            //
            var nsList = NameServerAddress.GetNameServersFromResponse(
                response,
                _preferIPv6,
                filterLoopbackAddresses: true);

            if (nsList.Count == 0)
                return; // fallback to next server, nothing useful here

            //
            // ---- Resolve glue from cache if available ----
            //
            nsList = await ResolveGlueFromCacheAsync(nsList);

            //
            // ---- Preserve / advance DNSSEC state ----
            //
            if (_ctx.Head.DnssecValidationState)
            {
                var dsResult = await TryGetDSFromResponseAsync(response, nextZoneCut);

                if (dsResult.HasOutcome)
                {
                    extendedErrors.AddRange(response.DnsClientExtendedErrors);

                    if (dsResult.IsUnsignedZone)
                    {
                        // unsigned zone — disable DNSSEC beyond this point
                        _ctx.Head.DnssecValidationState = false;
                        _ctx.Head.LastDSRecords = null;
                    }
                    else if (dsResult.HasDsRecords)
                    {
                        _ctx.Head.LastDSRecords = dsResult.DsRecords;
                    }
                }
            }

            //
            // ---- Commit transition to new zone ----
            //
            _ctx.Head.ZoneCut = nextZoneCut;
            _ctx.Head.NameServers = OrderNameServersForPerformance(nsList);
            _ctx.Head.NameServerIndex = 0;
            _ctx.Head.HopCount++;
            _ctx.Head.LastResponse = null;

            //
            // ---- Register speculative async NS resolution ----
            //
            if (_asyncNsResolution)
                RegisterAsyncGlueResolutionTasks(nsList);
        }

        //
        // -------------------------------
        //  DNSSEC — DS extraction helper
        // -------------------------------
        //
        private async Task<DsLookupResult> TryGetDSFromResponseAsync(
                                                                    DnsDatagram response,
                                                                    string owner)
        {
            return await DnssecUtilities.TryGetDSFromResponseAsync(
                response,
                owner,
                _cache);
        }


        //
        // -------------------------------
        //  Glue resolution from cache
        // -------------------------------
        //
        private async Task<List<NameServerAddress>> ResolveGlueFromCacheAsync(
            List<NameServerAddress> nsList)
        {
            var resolved = new List<NameServerAddress>(nsList.Count);

            foreach (var ns in nsList)
            {
                // already has glue — keep as-is
                if (ns.IPEndPoint is not null)
                {
                    resolved.Add(ns);
                    continue;
                }

                var host = ns.DomainEndPoint.Address.ToLowerInvariant();

                var cached = await _cache.QueryAsync(
                    new DnsDatagram(
                        0,
                        isResponse: false,
                        DnsOpcode.StandardQuery,
                        authoritativeAnswer: false,
                        truncation: false,
                        recursionDesired: false,
                        recursionAvailable: false,
                        authenticData: false,
                        checkingDisabled: false,
                        DnsResponseCode.NoError,
                        new[]
                        {
                    new DnsQuestionRecord(
                        host,
                        DnsResourceRecordType.A,
                        DnsClass.IN)
                        }),
                    serveStale: false,
                    findClosestNameServers: false,
                    resetExpiry: false);

                if (cached is null)
                {
                    resolved.Add(ns);
                    continue;
                }

                IPAddress glue = null;

                foreach (var rr in cached.Answer)
                {
                    switch (rr.Type)
                    {
                        case DnsResourceRecordType.A:
                            if (rr.RDATA is DnsARecordData a)
                                glue = a.Address;
                            break;

                        case DnsResourceRecordType.AAAA:
                            if (rr.RDATA is DnsAAAARecordData aaaa)
                                glue = aaaa.Address;
                            break;
                    }

                    if (glue is not null)
                        break;
                }

                if (glue is null)
                {
                    resolved.Add(ns);
                    continue;
                }

                // Clone NS with resolved glue address
                resolved.Add(ns.Clone(glue));
            }

            return resolved;
        }

        //
        // -------------------------------
        //  Ordering logic matches legacy behavior
        // -------------------------------
        //
        private List<NameServerAddress> OrderNameServersForPerformance(
            List<NameServerAddress> list)
        {
            list.Shuffle();

            list.Sort((a, b) =>
            {
                bool aResolved = a.IPEndPoint is not null;
                bool bResolved = b.IPEndPoint is not null;

                if (aResolved && !bResolved) return -1;
                if (!aResolved && bResolved) return 1;

                if (_preferIPv6)
                {
                    bool a6 = a.IPEndPoint?.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
                    bool b6 = b.IPEndPoint?.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;

                    if (a6 && !b6) return -1;
                    if (!a6 && b6) return 1;
                }

                return 0;
            });

            return list;
        }

        //
        // -------------------------------
        //  Async speculative NS resolution
        // -------------------------------
        //
        private void RegisterAsyncGlueResolutionTasks(List<NameServerAddress> list)
        {
            if (_asyncTasks is null)
                return;

            int maxTasks = Math.Min(list.Count, 4);

            foreach (var ns in list)
            {
                if (ns.IPEndPoint is null &&
                    _asyncTasks.TryAdd(ns.DomainEndPoint.Address.ToLowerInvariant(), null))
                {
                    if (--maxTasks <= 0)
                        return;
                }
            }
        }
    }
}
