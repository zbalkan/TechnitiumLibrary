using System;
using System.Collections.Generic;
using TechnitiumLibrary.Net.Dns.EDnsOptions;

namespace TechnitiumLibrary.Net.Dns
{
    internal sealed class ResolutionStateRecorder
    {
        private readonly QueryContext _ctx;
        private readonly IDnsCache _cache;
        private readonly List<EDnsExtendedDnsErrorOptionData> _ede;

        public ResolutionStateRecorder(
            QueryContext ctx,
            IDnsCache cache,
            List<EDnsExtendedDnsErrorOptionData> extendedDnsErrors)
        {
            _ctx = ctx;
            _cache = cache;
            _ede = extendedDnsErrors;
        }

        /// <summary>
        /// Called when a transport-level failure occurs
        /// (timeout, socket error, I/O error, etc.).
        /// </summary>
        public void RecordTransportFailure(Exception? ex)
        {
            _ctx.Head.LastException = ex;
            _ctx.Head.LastResponse = null;
        }

        /// <summary>
        /// Called when a validated DNS response is received.
        /// Updates resolver head state and optionally caches.
        /// </summary>
        public void RecordResponse(
            DnsDatagram response,
            List<EDnsExtendedDnsErrorOptionData> extendedErrors)
        {
            _ctx.Head.LastResponse = response;
            _ctx.Head.LastException = null;

            if (extendedErrors.Count > 0)
                response.AddDnsClientExtendedError(extendedErrors);

            //
            // Only cache responses that are suitable:
            // - standard answers
            // - NXDOMAIN / NODATA
            // - validated referrals
            //
            // Bad-cache insertion rules remain unchanged from original design.
            //
            if (IsCacheable(response))
                _cache.CacheResponse(response);
        }

        private static bool IsCacheable(DnsDatagram resp)
        {
            if (resp is null)
                return false;

            if (resp.Answer.Count > 0)
                return true;

            if (resp.RCODE == DnsResponseCode.NxDomain ||
                resp.RCODE == DnsResponseCode.NoError)
                return true;

            if (resp.Authority.Count > 0)
                return true;

            return false;
        }
    }
}
