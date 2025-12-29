using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Dns
{
    internal sealed class DnssecValidationController
    {
        private readonly QueryContext _ctx;
        private readonly IDnsCache _cache;
        private readonly ushort _udpPayloadSize;

        public DnssecValidationController(
            QueryContext ctx,
            IDnsCache cache,
            ushort udpPayloadSize)
        {
            _ctx = ctx;
            _cache = cache;
            _udpPayloadSize = udpPayloadSize;
        }

        public Task<DnsDatagram> ProcessAsync(
            DnsDatagram response,
            List<EDnsExtendedDnsErrorOptionData> extendedErrors,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // DNSSEC disabled → nothing to do
            if (!_ctx.Head.DnssecValidationState)
                return Task.FromResult(response);

            //
            // If response already carries a DNSSEC status
            // we trust the classification applied earlier in the pipeline.
            //
            if (response.Answer.Count > 0 &&
                response.Answer[0].DnssecStatus != DnssecStatus.Disabled)
            {
                return Task.FromResult(response);
            }

            //
            // DS-chain context — parent zone required DS
            //
            if (_ctx.Head.LastDSRecords is not null)
            {
                HandleDelegationDnssec(response, extendedErrors);
                return Task.FromResult(response);
            }

            //
            // If there are no DNSSEC records at all
            // treat response as INDETERMINATE rather than BOGUS
            //
            if (!ContainsAnyDnssecProof(response))
            {
                extendedErrors.Add(new EDnsExtendedDnsErrorOptionData(
                    EDnsExtendedDnsErrorCode.DnssecIndeterminate,
                    "No DNSSEC proof material present"));

                response.AddDnsClientExtendedError(
                    EDnsExtendedDnsErrorCode.DnssecIndeterminate,
                    "No DNSSEC proof material present");

                // allow resolver to continue but mark trust chain broken
                _ctx.Head.DnssecValidationState = false;
                _ctx.Head.LastDSRecords = null;
            }

            return Task.FromResult(response);
        }

        private void HandleDelegationDnssec(
            DnsDatagram response,
            List<EDnsExtendedDnsErrorOptionData> extendedErrors)
        {
            bool sawDs = false;
            bool sawNs = false;

            foreach (var rr in response.Authority)
            {
                if (rr.Type == DnsResourceRecordType.DS)
                    sawDs = true;

                if (rr.Type == DnsResourceRecordType.NS)
                    sawNs = true;
            }

            //
            // insecure delegation — NS but no DS = allowed per RFC
            //
            if (sawNs && !sawDs)
            {
                _ctx.Head.DnssecValidationState = false;
                _ctx.Head.LastDSRecords = null;
                return;
            }

            //
            // DS chain continues — track DS for next hop
            //
            if (sawDs)
            {
                _ctx.Head.LastDSRecords = response.Authority;
                return;
            }

            //
            // Expected DS but none found → treat as BOGUS
            //
            extendedErrors.Add(new EDnsExtendedDnsErrorOptionData(
                EDnsExtendedDnsErrorCode.DnssecBogus,
                "Expected DS but none found in authority section"));

            response.AddDnsClientExtendedError(
                EDnsExtendedDnsErrorCode.DnssecBogus,
                "Expected DS but none found in authority section");

            _ctx.Head.LastException =
                new InvalidOperationException("DNSSEC chain validation failed (missing DS)");

            _ctx.Head.DnssecValidationState = false;
        }

        private static bool ContainsAnyDnssecProof(DnsDatagram resp)
        {
            foreach (var rr in resp.Answer)
            {
                switch (rr.Type)
                {
                    case DnsResourceRecordType.RRSIG:
                    case DnsResourceRecordType.DNSKEY:
                    case DnsResourceRecordType.DS:
                        return true;
                }
            }

            foreach (var rr in resp.Authority)
            {
                switch (rr.Type)
                {
                    case DnsResourceRecordType.RRSIG:
                    case DnsResourceRecordType.NSEC:
                    case DnsResourceRecordType.NSEC3:
                    case DnsResourceRecordType.DS:
                        return true;
                }
            }

            return false;
        }
    }
}
