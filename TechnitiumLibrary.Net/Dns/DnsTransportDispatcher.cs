using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Dns
{
    internal sealed class DnsTransportDispatcher
    {
        private readonly NetProxy? _proxy;
        private readonly int _concurrency;
        private readonly int _retries;
        private readonly int _timeout;
        private readonly ushort _udpPayloadSize;

        public DnsTransportDispatcher(
            NetProxy? proxy,
            int concurrency,
            int retries,
            int timeout,
            ushort udpPayloadSize)
        {
            _proxy = proxy;
            _concurrency = concurrency;
            _retries = retries;
            _timeout = timeout;
            _udpPayloadSize = udpPayloadSize;
        }

        /// <summary>
        /// Builds a request datagram, issues the query to the selected
        /// nameserver(s), and returns the raw response (or failure state).
        /// This class only performs transport; resolver semantics remain outside.
        /// </summary>
        public async Task<DnsTransportResult> QueryAsync(
            QueryContext ctx,
            NameServerSelection selection,
            DnsQuestionRecord question,
            bool randomizeName,
            bool dnssecValidation,
            EDnsOption[] eDnsClientSubnetOption,
            List<DnsDatagram>? rawResponses,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // Selection always yields either batch or single
            var servers = selection.Batch ??
                          new[] { selection.Single! };

            var dnsClient = CreateClientForServers(servers.ToList(), randomizeName);

            var request = BuildRequestDatagram(
                ctx,
                question,
                dnssecValidation,
                eDnsClientSubnetOption);

            try
            {
                var response = await dnsClient.InternalResolveAsync(request, cancellationToken);

                return DnsTransportResult.Success(response, request);
            }
            catch (Exception ex)
            {
                return DnsTransportResult.Error(ex, request);
            }
        }

        private DnsClient CreateClientForServers(
            List<NameServerAddress> servers,
            bool randomizeName)
        {
            // Always construct a dedicated per-dispatch call client instance.
            var client = new DnsClient(servers);

            // NOTE: DNSSEC runtime behavior is governed by the caller
            // and applied during validation — this layer only transports.

            return client;
        }

        private DnsDatagram BuildRequestDatagram(
            QueryContext ctx,
            DnsQuestionRecord question,
            bool dnssecValidation,
            EDnsOption[] eDnsClientSubnetOption)
        {
            // ECS should apply only when at top-level stack & non-root zone cut
            bool includeEcs =
                ctx.Stack.Count == 0 &&
                !string.IsNullOrEmpty(ctx.Head.ZoneCut) &&
                ctx.Head.ZoneCut!.Contains('.');

            return new DnsDatagram(
                ID: 0,
                isResponse: false,
                OPCODE: DnsOpcode.StandardQuery,
                authoritativeAnswer: false,
                truncation: false,
                recursionDesired: false,
                recursionAvailable: false,
                authenticData: false,
                checkingDisabled: false,
                RCODE: DnsResponseCode.NoError,
                question: new[] { question },
                answer: null,
                authority: null,
                additional: null,
                udpPayloadSize: _udpPayloadSize,
                ednsFlags: dnssecValidation
                    ? EDnsHeaderFlags.DNSSEC_OK
                    : EDnsHeaderFlags.None,
                options: includeEcs
                    ? eDnsClientSubnetOption
                    : null);
        }
    }

    internal readonly struct DnsTransportResult
    {
        public bool IsSuccess { get; }
        public DnsDatagram? Response { get; }
        public Exception? Exception { get; }
        public DnsDatagram Request { get; }

        private DnsTransportResult(
            bool success,
            DnsDatagram? response,
            Exception? exception,
            DnsDatagram request)
        {
            IsSuccess = success;
            Response = response;
            Exception = exception;
            Request = request;
        }

        public static DnsTransportResult Success(DnsDatagram response, DnsDatagram request) =>
            new(true, response, null, request);

        public static DnsTransportResult Error(Exception ex, DnsDatagram request) =>
            new(false, null, ex, request);
    }
}
