using System;
using System.Collections.Generic;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Dns
{
    /// <summary>
    /// Produces final failure responses (SERVFAIL, NOERROR-empty, cached NXDOMAIN etc.)
    /// when the resolver reaches a terminal state with no further transitions.
    /// </summary>
    internal sealed class FailureOutcomeSynthesizer
    {
        private readonly QueryContext _ctx;
        private readonly IDnsCache _cache;
        private readonly bool _minimalResponse;

        public FailureOutcomeSynthesizer(
            QueryContext ctx,
            IDnsCache cache,
            bool minimalResponse)
        {
            _ctx = ctx;
            _cache = cache;
            _minimalResponse = minimalResponse;
        }

        /// <summary>
        /// Builds a terminal outcome response based on the last recorded
        /// state and resolver behaviour rules.
        /// </summary>
        public DnsDatagram BuildFailureResponse(
            List<EDnsExtendedDnsErrorOptionData> extendedErrors)
        {
            var head = _ctx.Head;
            var last = head.LastResponse;

            //
            // Case 1 — We already have a response, just sanitize / trim it
            //
            if (last is not null)
            {
                if (_minimalResponse)
                    last = MakeMinimal(last);

                // Cache failure-type responses
                if (last.RCODE != DnsResponseCode.NoError)
                    _cache.CacheResponse(last);

                return last;
            }

            //
            // Case 2 — No server ever answered → Synthesize SERVFAIL
            //
            var failure = new DnsDatagram(
                0,
                isResponse: true,
                DnsOpcode.StandardQuery,
                authoritativeAnswer: false,
                truncation: false,
                recursionDesired: false,
                recursionAvailable: false,
                authenticData: false,
                checkingDisabled: false,
                DnsResponseCode.ServerFailure,
                new[] { head.Question });

            if (extendedErrors.Count > 0)
                failure.AddDnsClientExtendedError(extendedErrors);

            failure.AddDnsClientExtendedError(
                EDnsExtendedDnsErrorCode.NoReachableAuthority,
                $"Resolution failed at {head.ZoneCut ?? "(root)"}");

            _cache.CacheResponse(failure);

            return failure;
        }

        private static DnsDatagram MakeMinimal(DnsDatagram response)
        {
            return new DnsDatagram(
                response.Identifier,
                true,
                DnsOpcode.StandardQuery,
                false,
                false,
                false,
                false,
                false,
                false,
                response.RCODE,
                response.Question,
                Array.Empty<DnsResourceRecord>(),
                Array.Empty<DnsResourceRecord>(),
                Array.Empty<DnsResourceRecord>());
        }
    }
}
