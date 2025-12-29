using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Dns
{
    internal sealed class ResponseClassifier
    {
        private readonly QueryContext _ctx;
        private readonly bool _minimalResponse;

        public ResponseClassifier(
            QueryContext ctx,
            bool minimalResponse)
        {
            _ctx = ctx;
            _minimalResponse = minimalResponse;
        }

        public Task<ResolverDecision> ClassifyAsync(
            DnsDatagram response,
            DnsQuestionRecord question,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            //
            // --- CASE 1: Terminal Answer / NXDOMAIN / NoData ---
            //
            if (response.Answer.Count > 0 ||
                response.RCODE == DnsResponseCode.NxDomain)
            {
                return Task.FromResult(
                    new ResolverDecision(
                        ResolverDecisionKind.ReturnAnswer,
                        _minimalResponse
                            ? GetMinimalResponseWithoutNSAndGlue(response)
                            : response));
            }

            //
            // --- CASE 2: Stack unwind (glue resolution complete) ---
            //
            if (_ctx.Stack.Count > 0 &&
                (ContainsAddressRecord(response) ||
                 ContainsDsRecord(response)))
            {
                return Task.FromResult(
                    new ResolverDecision(
                        ResolverDecisionKind.UnwindStack,
                        response));
            }

            //
            // --- CASE 3: Delegation found ---
            //
            if (response.Authority.Count > 0 &&
                response.FindFirstAuthorityRecord().Type == DnsResourceRecordType.NS)
            {
                return Task.FromResult(
                    new ResolverDecision(
                        ResolverDecisionKind.DelegationTransition,
                        response));
            }

            //
            // --- CASE 4: QNAME minimization fallback ---
            //
            if (question.ZoneCut is not null &&
                !question.Name.Equals(question.MinimizedName, StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(
                    new ResolverDecision(
                        ResolverDecisionKind.RetryWithQNameMinimization,
                        response));
            }

            //
            // --- CASE 5: Try next server ---
            //
            return Task.FromResult(
                new ResolverDecision(
                    ResolverDecisionKind.ContinueNextServer));
        }

        private static bool ContainsAddressRecord(DnsDatagram r) =>
            r.Answer.Any(a =>
                a.Type == DnsResourceRecordType.A ||
                a.Type == DnsResourceRecordType.AAAA);

        private static bool ContainsDsRecord(DnsDatagram r) =>
            r.Answer.Any(a => a.Type == DnsResourceRecordType.DS);


        /// <summary>
        /// Matches the legacy minimal-response behaviour.
        /// </summary>
        private static DnsDatagram GetMinimalResponseWithoutNSAndGlue(DnsDatagram response)
        {
            return response.Clone(
               answer: response.Answer,
               authority: Array.Empty<DnsResourceRecord>(),
               additional: Array.Empty<DnsResourceRecord>());
        }
    }
}
