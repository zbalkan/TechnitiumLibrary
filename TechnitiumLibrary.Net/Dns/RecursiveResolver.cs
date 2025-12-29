using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Dns
{
    internal sealed class ResolverConfig
    {
        public NetProxy? Proxy { get; init; }
        public bool PreferIPv6 { get; init; }
        public bool RandomizeName { get; init; }
        public bool QNameMinimization { get; init; }
        public bool DnssecValidation { get; init; }
        public ushort UdpPayloadSize { get; init; }
        public int Retries { get; init; }
        public int Timeout { get; init; }
        public int Concurrency { get; init; }
        public int MaxStackCount { get; init; }
    }

    internal sealed class RecursiveResolver
    {
        private readonly ResolverConfig _config;
        private readonly IDnsCache _cache;

        public RecursiveResolver(ResolverConfig config, IDnsCache? cache)
        {
            _config = config;
            _cache = cache is not null ? cache : new DnsCache();
        }

        /// <summary>
        /// Public entry point for recursive resolution.
        /// Creates per-query state, dispatcher, and runs the stack processor.
        /// </summary>
        public async Task<DnsDatagram> ResolveAsync(
            DnsQuestionRecord question,
            IDnsCache? cache = null,
            bool qnameMinimization = false,
            bool dnssecValidation = false,
            NetworkAddress? eDnsClientSubnet = null,
            bool minimalResponse = false,
            bool asyncNsResolution = false,
            List<DnsDatagram>? rawResponses = null,
            CancellationToken cancellationToken = default)
        {
            cache ??= new DnsCache();

            if ((_config.UdpPayloadSize < 512) && (dnssecValidation || (eDnsClientSubnet is not null)))
                throw new ArgumentOutOfRangeException(nameof(_config.UdpPayloadSize),
                    "EDNS cannot be disabled when DNSSEC or ECS is enabled.");

            if (qnameMinimization)
            {
                question = question.Clone();
                question.ZoneCut = string.Empty;
            }

            var extendedDnsErrors = new List<EDnsExtendedDnsErrorOptionData>();
            var asyncNsResolutionTasks = asyncNsResolution
                ? new Dictionary<string, object>()
                : null;

            var ecsOptions = EDnsClientSubnetOptionData.GetEDnsClientSubnetOption(eDnsClientSubnet);

            //
            // ---- create initial HEAD state ----
            //
            var head = new InternalState
            {
                Question = question,
                ZoneCut = string.Empty,
                DnssecValidationState = dnssecValidation,
                LastDSRecords = null,
                NameServers = null,
                NameServerIndex = 0,
                HopCount = 0,
                LastResponse = null,
                LastException = null
            };

            var queryId = Guid.NewGuid();
            var ctx = QueryContextStore.Instance.Create(queryId, head);

            //
            // ---- per-query dispatcher (transport only) ----
            //
            var dispatcher = new DnsTransportDispatcher(
                proxy: _config.Proxy,
                concurrency: _config.Concurrency,
                retries: _config.Retries,
                timeout: _config.Timeout,
                udpPayloadSize: _config.UdpPayloadSize);

            try
            {
                return await RunStackLoop(
                    queryId: queryId,
                    ctx: ctx,
                    dispatcher: dispatcher,
                    question: question,
                    cache: cache,
                    preferIPv6: _config.PreferIPv6,
                    randomizeName: _config.RandomizeName,
                    qnameMinimization: qnameMinimization,
                    dnssecValidation: dnssecValidation,
                    eDnsClientSubnet: eDnsClientSubnet,
                    retries: _config.Retries,
                    timeout: _config.Timeout,
                    concurrency: _config.Concurrency,
                    maxStackCount: _config.MaxStackCount,
                    minimalResponse: minimalResponse,
                    asyncNsResolution: asyncNsResolution,
                    rawResponses: rawResponses,
                    eDnsClientSubnetOption: ecsOptions,
                    extendedDnsErrors: extendedDnsErrors,
                    asyncNsResolutionTasks: asyncNsResolutionTasks,
                    cancellationToken: cancellationToken);
            }
            finally
            {
                QueryContextStore.Instance.Remove(queryId);
            }
        }

        private static DnsDatagram BuildStackLimitFailure(
                    DnsQuestionRecord question,
                    List<EDnsExtendedDnsErrorOptionData> extendedDnsErrors,
                    NetworkAddress? ecs)
        {
            var failure = new DnsDatagram(
                0, true, DnsOpcode.StandardQuery,
                false, false, false, false, false, false,
                DnsResponseCode.ServerFailure,
                new[] { question });

            if (extendedDnsErrors.Count > 0)
                failure.AddDnsClientExtendedError(extendedDnsErrors);

            failure.AddDnsClientExtendedError(
                EDnsExtendedDnsErrorCode.NoReachableAuthority,
                $"Recursion stack limit reached for {question}");

            if (ecs is not null)
                failure.SetShadowEDnsClientSubnetOption(
                    new EDnsClientSubnetOptionData(
                        ecs.PrefixLength,
                        ecs.PrefixLength,
                        ecs.Address));

            return failure;
        }

        private async Task<List<NameServerAddress>> GetRootServersUsingRootHintsAsync(
            IDnsCache cache,
            NetProxy? proxy,
            bool preferIPv6,
            ushort udpPayloadSize,
            bool dnssecValidation,
            int retries,
            int timeout,
            int concurrency,
            CancellationToken cancellationToken = default)
        {
            //
            // ---- build shuffled root-hint server list (same semantics) ----
            //
            List<NameServerAddress> rootHints = RootHints.GetShuffled(preferIPv6);


            //
            // ---- build dispatcher (transport only) ----
            //
            var dispatcher = new DnsTransportDispatcher(
                proxy: proxy,
                concurrency: concurrency,
                retries: retries,
                timeout: timeout,
                udpPayloadSize: udpPayloadSize);

            var ctx = new QueryContext(Guid.NewGuid(), new InternalState
            {
                DnssecValidationState = dnssecValidation,
                ZoneCut = "",
                NameServers = rootHints,
                NameServerIndex = 0
            });

            var question = new DnsQuestionRecord(
                name: "",
                type: DnsResourceRecordType.NS,
                @class: DnsClass.IN);

            //
            // ---- issue priming query over transport ----
            //
            var result = await dispatcher.QueryAsync(
                ctx,
                NameServerSelection.ResolvedBatch(rootHints),
                question,
                randomizeName: false,
                dnssecValidation: dnssecValidation,
                eDnsClientSubnetOption: Array.Empty<EDnsOption>(),
                rawResponses: null,
                cancellationToken);

            if (!result.IsSuccess || result.Response is null)
                throw new DnsClientException("Root priming query failed.", result.Exception);

            var response = result.Response;

            //
            // ---- validate priming-query response (unchanged semantics) ----
            //
            if (response.RCODE != DnsResponseCode.NoError)
                throw new DnsClientFailureResponseException(
                    $"DnsClient failed priming query '{question}'. RCODE: {response.RCODE}",
                    response);

            if (response.Answer.Count == 0 || response.Authority.Count > 0 || response.Additional.Count == 0)
                throw new DnsClientFailureResponseException(
                    $"DnsClient failed priming query '{question}'. Response missing answer/additional.",
                    response);

            //
            // ---- cache priming response ----
            //
            cache.CacheResponse(response);

            //
            // ---- extract NS + glue and shuffle ----
            //
            var rootServers = NameServerAddress.GetNameServersFromResponse(response, preferIPv6, true);

            // replicate previous loopback-filter behaviour
            rootServers.RemoveAll(ns =>
                ns.IPEndPoint?.Address is not null &&
                IPAddress.IsLoopback(ns.IPEndPoint.Address));

            rootServers.Shuffle();

            return rootServers;
        }

        private async Task<(bool flowControl, DnsDatagram? value)> QueryCacheAsync(
                    Guid queryId,
                    DnsQuestionRecord question,
                    IDnsCache cache,
                    bool preferIPv6,
                    bool randomizeName,
                    bool qnameMinimization,
                    bool dnssecValidation,
                    int retries,
                    int timeout,
                    int concurrency,
                    int maxStackCount,
                    bool asyncNsResolution,
                    EDnsOption[] eDnsClientSubnetOption,
                    List<EDnsExtendedDnsErrorOptionData> extendedErrors,
                    Dictionary<string, object>? asyncNsResolutionTasks)
        {
            var ctx = QueryContextStore.Instance.Get(queryId);

            // Ask cache whether it can satisfy the query or provide referral authority
            var cached = await cache.QueryAsync(
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
                    new[] { question }),
                serveStale: false,
                findClosestNameServers: true,
                resetExpiry: false);

            // Nothing in cache → continue resolver pipeline
            if (cached is null)
                return (flowControl: true, value: null);

            // Record last cache result in head state
            ctx.Head.LastResponse = cached;

            //
            // Terminal cached answers (stop resolution)
            //
            if (cached.Answer.Count > 0 ||
                cached.RCODE == DnsResponseCode.NxDomain ||
                cached.RCODE == DnsResponseCode.YXDomain)
            {
                return (flowControl: false, value: cached);
            }

            //
            // Cache returned referral NS set → seed next hop
            //
            if (cached.Authority.Count > 0)
            {
                var nsRecords = NameServerAddress.GetNameServersFromResponse(cached, preferIPv6, true);
                if (nsRecords.Count > 0)
                {
                    ctx.Head.ZoneCut = cached.FindFirstAuthorityRecord().Name;
                    ctx.Head.NameServers = nsRecords;
                    ctx.Head.NameServerIndex = 0;
                    ctx.Head.HopCount++;
                    ctx.Head.LastException = null;

                    return (flowControl: true, value: null);
                }
            }

            //
            // Negative / empty cache responses
            //
            return (flowControl: false, value: cached);
        }

        private async Task<(bool flowControl, DnsDatagram? value)?> QueryNameServers(Guid queryId,
                                                                                             DnsQuestionRecord question,
                                                                                             IDnsCache cache,
                                                                                             NetProxy? proxy,
                                                                                             bool preferIPv6,
                                                                                             ushort udpPayloadSize,
                                                                                             bool randomizeName,
                                                                                             bool qnameMinimization,
                                                                                             bool dnssecValidation,
                                                                                             int retries,
                                                                                             int timeout,
                                                                                             int concurrency,
                                                                                             int maxStackCount,
                                                                                             bool minimalResponse,
                                                                                             bool asyncNsResolution,
                                                                                             List<DnsDatagram> rawResponses,
                                                                                             EDnsOption[] eDnsClientSubnetOption,
                                                                                             List<EDnsExtendedDnsErrorOptionData> extendedDnsErrors,
                                                                                             Dictionary<string, object> asyncNsResolutionTasks,
                                                                                             CancellationToken cancellationToken)
        {
            var ctx = QueryContextStore.Instance.Get(queryId);

            var iterator = new NameServerIterator(ctx, preferIPv6);
            var glue = new GlueResolutionCoordinator(ctx, dnssecValidation, preferIPv6, asyncNsResolution, asyncNsResolutionTasks);
            var transport = new DnsTransportDispatcher(proxy, concurrency, retries, timeout, udpPayloadSize);
            var sanitizer = new ResponseSanitizerPipeline(ctx);
            var validator = new DnssecValidationController(ctx, cache, udpPayloadSize);
            var recorder = new ResolutionStateRecorder(ctx, cache, extendedDnsErrors);
            var classifier = new ResponseClassifier(ctx, minimalResponse);
            var referrals = new ReferralTransitionEngine(ctx, cache, preferIPv6, asyncNsResolution, asyncNsResolutionTasks);
            var qminFallback = new QNameMinimizationFallbackController(ctx);
            var finalizer = new FailureOutcomeSynthesizer(ctx, cache, minimalResponse);

            while (iterator.HasMore())
            {
                var selection = iterator.SelectNextBatch();

                if (selection.RequiresGlueResolution)
                {
                    glue.PushGlueLookupFrame(selection.Single!, question);
                    return (flowControl: false, value: null);
                }

                var response = await transport.QueryAsync(
                    ctx, selection, question,
                    randomizeName,
                    dnssecValidation,
                    eDnsClientSubnetOption,
                    rawResponses,
                    cancellationToken);

                if (!response.IsSuccess)
                {
                    recorder.RecordTransportFailure(response.Exception);
                    iterator.MoveNext();
                    continue;
                }

                var sanitized = sanitizer.Apply(response.Response);

                var validated = await validator.ProcessAsync(
                    sanitized,
                    extendedDnsErrors,
                    cancellationToken);

                recorder.RecordResponse(validated, extendedDnsErrors);

                var decision = await classifier.ClassifyAsync(
                    validated,
                    question,
                    cancellationToken);

                switch (decision.Kind)
                {
                    case ResolverDecisionKind.ReturnAnswer:
                        return (flowControl: false, value: decision.Response);

                    case ResolverDecisionKind.UnwindStack:
                        decision.ApplyUnwind();
                        return null;

                    case ResolverDecisionKind.DelegationTransition:
                        await referrals.MoveToNextZoneAsync(decision, extendedDnsErrors);
                        return null;

                    case ResolverDecisionKind.RetryWithQNameMinimization:
                        qminFallback.Apply();
                        iterator.RewindToCurrent();
                        continue;

                    case ResolverDecisionKind.ContinueNextServer:
                        iterator.MoveNext();
                        continue;
                }
            }

            // no usable server → allow outer resolver loop to handle
            return (flowControl: true, value: null);
        }

        //
        // This is the refactored stack driver. It delegates frame-processing
        // to the ResolverFrameProcessor and transport to DnsTransportDispatcher.
        //
        private async Task<DnsDatagram> RunStackLoop(
            Guid queryId,
            QueryContext ctx,
            DnsTransportDispatcher dispatcher,
            DnsQuestionRecord question,
            IDnsCache cache,
            bool preferIPv6,
            bool randomizeName,
            bool qnameMinimization,
            bool dnssecValidation,
            NetworkAddress? eDnsClientSubnet,
            int retries,
            int timeout,
            int concurrency,
            int maxStackCount,
            bool minimalResponse,
            bool asyncNsResolution,
            List<DnsDatagram>? rawResponses,
            EDnsOption[] eDnsClientSubnetOption,
            List<EDnsExtendedDnsErrorOptionData> extendedDnsErrors,
            Dictionary<string, object>? asyncNsResolutionTasks,
            CancellationToken cancellationToken)
        {
            var processor = new ResolverFrameProcessor(queryId, cache);

            for (; ; )
            {
                cancellationToken.ThrowIfCancellationRequested();

                // stack-limit guard
                if (ctx.Stack.Count > maxStackCount)
                {
                    while (ctx.Stack.Count > 0)
                        ctx.Stack.Pop();

                    var failure = BuildStackLimitFailure(
                        question,
                        extendedDnsErrors,
                        eDnsClientSubnet);

                    cache.CacheResponse(failure);

                    throw new DnsClientException(
                        $"DnsClient recursive resolution exceeded the maximum stack count for domain: {question.Name.ToLowerInvariant()}");
                }

                // cache stage
                var (flow, cached) = await QueryCacheAsync(
                    queryId,
                    question,
                    cache,
                    preferIPv6,
                    randomizeName,
                    qnameMinimization,
                    dnssecValidation,
                    retries,
                    timeout,
                    concurrency,
                    maxStackCount,
                    asyncNsResolution,
                    eDnsClientSubnetOption,
                    extendedDnsErrors,
                    asyncNsResolutionTasks);

                if (!flow)
                    return cached;

                // NS priming if no current NS set
                if (ctx.Head.NameServers is null || ctx.Head.NameServers.Count == 0)
                {
                    ctx.Head.ZoneCut = string.Empty;
                    ctx.Head.NameServers = await GetRootServersUsingRootHintsAsync(
                        cache,
                        _config.Proxy,
                        preferIPv6,
                        _config.UdpPayloadSize,
                        dnssecValidation,
                        retries,
                        timeout,
                        concurrency,
                        cancellationToken);

                    ctx.Head.NameServerIndex = 0;
                    ctx.Head.LastResponse = null;
                }

                // run one resolver-frame step
                var ev = await processor.StepAsync(
                    question,
                    async () => await QueryNameServers(
                        queryId,
                        question,
                        cache,
                        _config.Proxy,
                        preferIPv6,
                        _config.UdpPayloadSize,
                        randomizeName,
                        qnameMinimization,
                        dnssecValidation,
                        retries,
                        timeout,
                        concurrency,
                        maxStackCount,
                        minimalResponse,
                        asyncNsResolution,
                        rawResponses,
                        eDnsClientSubnetOption,
                        extendedDnsErrors,
                        asyncNsResolutionTasks,
                        cancellationToken),
                    null,
                    extendedDnsErrors,
                    null,
                    false,
                    cancellationToken);

                switch (ev.Type)
                {
                    case ResolverEventType.ReturnAnswer:
                        return ev.Response!;

                    case ResolverEventType.PushDsFrame:
                        ctx.Stack.Push(ctx.Head);
                        ctx.Head = ev.NewFrame!;
                        break;

                    case ResolverEventType.UnwindSkipServer:
                        ctx.Head = ctx.Stack.Pop();
                        break;

                    case ResolverEventType.TerminalFailure:
                        return ev.Response!;
                }
            }
        }

        private static int CompareNameServersToPreferIPv6(NameServerAddress a, NameServerAddress b)
        {
            var afA = a.IPEndPoint.Address.AddressFamily;
            var afB = b.IPEndPoint.Address.AddressFamily;
            return afA.CompareTo(afB);
        }

        private static void EnsureOneIpv4NameServerAtTop(List<NameServerAddress> list)
        {
            var ipv4 = list.Find(x =>
                x.IPEndPoint.AddressFamily ==
                System.Net.Sockets.AddressFamily.InterNetwork);

            if (ipv4 != null)
            {
                list.Remove(ipv4);
                list.Insert(0, ipv4);
            }
        }
    }
}
