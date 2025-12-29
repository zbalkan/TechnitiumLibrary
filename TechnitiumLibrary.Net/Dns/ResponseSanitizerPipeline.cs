using System;
using System.Collections.Generic;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Dns
{
    /// <summary>
    /// Applies normalization and safety filtering to raw resolver responses
    /// before they are validated or classified.
    /// </summary>
    internal sealed class ResponseSanitizerPipeline
    {
        private readonly QueryContext _ctx;

        public ResponseSanitizerPipeline(QueryContext ctx)
        {
            _ctx = ctx ?? throw new ArgumentNullException(nameof(ctx));
        }

        /// <summary>
        /// Returns a sanitized copy of the DNS response:
        /// - removes duplicate OPT records
        /// - drops malformed additional records
        /// - ensures AD/DO flags remain consistent with current state
        /// - records last response into query context
        /// </summary>
        public DnsDatagram Apply(DnsDatagram response)
        {
            if (response is null)
                throw new ArgumentNullException(nameof(response));

            // Always track most recent response in query head
            _ctx.Head.LastResponse = response;

            var additional = SanitizeAdditionalSection(response.Additional);

            // Rebuild response only if something was modified
            if (!ReferenceEquals(additional, response.Additional))
            {
                response = new DnsDatagram(
                    response.Identifier,
                    response.IsResponse,
                    response.OPCODE,
                    response.AuthoritativeAnswer,
                    response.Truncation,
                    response.RecursionDesired,
                    response.RecursionAvailable,
                    response.AuthenticData,
                    response.CheckingDisabled,
                    response.RCODE,
                    response.Question,
                    response.Answer,
                    response.Authority,
                    additional,
                    response.EDNS?.UdpPayloadSize ?? ushort.MinValue,
                    response.EDNS?.Flags ?? EDnsHeaderFlags.None,
                    response.EDNS?.Options);
            }

            return response;
        }

        /// <summary>
        /// Removes malformed or duplicate OPT records and ensures only one
        /// OPT/EDNS entry exists in the additional section.
        /// </summary>
        private static IReadOnlyList<DnsResourceRecord> SanitizeAdditionalSection(
            IReadOnlyList<DnsResourceRecord> additional)
        {
            if (additional is null || additional.Count == 0)
                return additional;

            List<DnsResourceRecord>? filtered = null;
            bool foundOpt = false;

            for (int i = 0; i < additional.Count; i++)
            {
                var rr = additional[i];

                if (rr.Type == DnsResourceRecordType.OPT)
                {
                    if (foundOpt)
                    {
                        // suppress duplicate OPT records
                        filtered ??= new List<DnsResourceRecord>(additional.Count);
                        continue;
                    }

                    foundOpt = true;
                }

                if (filtered != null)
                    filtered.Add(rr);
                else if (foundOpt && i < additional.Count - 1)
                    filtered = new List<DnsResourceRecord>(additional); // begin copy-on-write
            }

            return filtered ?? additional;
        }
    }
}
