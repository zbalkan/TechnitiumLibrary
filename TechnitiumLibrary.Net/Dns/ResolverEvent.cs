using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Dns
{
    public enum ResolverEventType
    {
        QueryServers,
        PushDsFrame,
        ReturnAnswer,
        UnwindSkipServer,
        UnwindDsFailure,
        TerminalFailure
    }

    public sealed record ResolverEvent(
        ResolverEventType Type,
        DnsDatagram? Response = null,
        DnsQuestionRecord? Question = null,
        InternalState? NewFrame = null);

    public sealed class ResolverFrameProcessor
    {
        private readonly Guid _id;
        private readonly IDnsCache _cache;

        public ResolverFrameProcessor(Guid id, IDnsCache cache)
        {
            _id = id;
            _cache = cache;
        }

        public async Task<ResolverEvent> StepAsync(
            DnsQuestionRecord question,
            Func<Task<(bool flowControl, DnsDatagram value)?>> queryServersAsync,
            Func<Task> triggerAsyncNsResolution,
            List<EDnsExtendedDnsErrorOptionData> ede,
            NetworkAddress? ecs,
            bool minimalResponse,
            CancellationToken ct)
        {
            var ctx = QueryContextStore.Instance.Get(_id);
            var head = ctx.Head;

            // DS prerequisite -> push DS frame (same semantic as before)
            if (head.LastDSRecords is not null &&
    !head.LastDSRecords[0].Name.Equals(head.ZoneCut, StringComparison.OrdinalIgnoreCase))
            {
                var dsQuestion = new DnsQuestionRecord(
                    head.ZoneCut,
                    DnsResourceRecordType.DS,
                    DnsClass.IN);

                var newFrame = new InternalState
                {
                    Question = dsQuestion,
                    ZoneCut = head.ZoneCut,
                    DnssecValidationState = head.DnssecValidationState,
                    LastDSRecords = head.LastDSRecords,
                    NameServers = head.NameServers,
                    NameServerIndex = 0,
                    HopCount = head.HopCount,
                    LastResponse = null,
                    LastException = null
                };

                return new ResolverEvent(
                    ResolverEventType.PushDsFrame,
                    Question: dsQuestion,
                    NewFrame: newFrame);
            }


            // Query name servers -> same QueryNameServers outcome
            var res = await queryServersAsync();
            if (!res.HasValue)
                return new ResolverEvent(ResolverEventType.UnwindSkipServer, Question: question);

            if (!res.Value.flowControl)
            {
                var dsQuestion = new DnsQuestionRecord(
                    head.ZoneCut,
                    DnsResourceRecordType.DS,
                    DnsClass.IN);

                var newFrame = new InternalState
                {
                    Question = dsQuestion,
                    ZoneCut = head.ZoneCut,
                    DnssecValidationState = head.DnssecValidationState,
                    LastDSRecords = head.LastDSRecords,
                    NameServers = head.NameServers,
                    NameServerIndex = 0,
                    HopCount = head.HopCount
                };

                return new ResolverEvent(
                    ResolverEventType.PushDsFrame,
                    Question: dsQuestion,
                    NewFrame: newFrame);
            }

            // No usable server result
            if (ctx.Stack.Count == 0)
            {
                await triggerAsyncNsResolution();

                var (terminal, throwable) =
                    BuildTerminalFailure(question, ctx.Head, _cache, ede, ecs, minimalResponse);

                if (terminal is not null)
                    return new ResolverEvent(
                        ResolverEventType.TerminalFailure,
                        Response: terminal);

                ExceptionDispatchInfo.Throw(throwable!);
            }

            // Unwind stack frame
            var lastQuestion = question;
            ctx.Head = ctx.Stack.Pop();

            switch (lastQuestion.Type)
            {
                case DnsResourceRecordType.A:
                case DnsResourceRecordType.AAAA:
                    ctx.Head.NameServerIndex++;
                    return new ResolverEvent(ResolverEventType.UnwindSkipServer, Question: lastQuestion);

                case DnsResourceRecordType.DS:
                    var failure = BuildDsFailure(lastQuestion, ctx.Head, _cache, ede, ecs);
                    throw new DnsClientResponseDnssecValidationException(
                        $"Attack detected! DNSSEC validation failed for {lastQuestion.Name.ToLowerInvariant()}",
                        ctx.Head.LastResponse ?? failure);
            }

            return new ResolverEvent(ResolverEventType.UnwindSkipServer, Question: lastQuestion);
        }
        private static (DnsDatagram? response, Exception? exception)
        BuildTerminalFailure(
            DnsQuestionRecord question,
            InternalState head,
            IDnsCache cache,
            List<EDnsExtendedDnsErrorOptionData> ede,
            NetworkAddress? ecs,
            bool minimalResponse)
        {
            // Case 1 — last response exists and matches question
            if (head.LastResponse is not null &&
                head.LastResponse.Question.Count > 0 &&
                head.LastResponse.Question[0].Equals(question))
            {
                if (ede.Count > 0)
                    head.LastResponse.AddDnsClientExtendedError(ede);

                if (minimalResponse)
                    return (GetMinimalResponseWithoutNSAndGlue(head.LastResponse), null);

                return (head.LastResponse, null);
            }

            //
            // Case 2 — synthesize + cache failure depending on LastException
            //

            DnsDatagram MakeBaseFailure()
            {
                var failure = new DnsDatagram(
                    0, true, DnsOpcode.StandardQuery,
                    false, false, false, false, false, false,
                    DnsResponseCode.ServerFailure,
                    new[] { question });

                if (ede.Count > 0)
                    failure.AddDnsClientExtendedError(ede);

                if (ecs is not null)
                    failure.SetShadowEDnsClientSubnetOption(
                        new EDnsClientSubnetOptionData(
                            ecs.PrefixLength, ecs.PrefixLength, ecs.Address));

                return failure;
            }

            if (head.LastException is null)
            {
                var failure = MakeBaseFailure();
                failure.AddDnsClientExtendedError(
                    EDnsExtendedDnsErrorCode.NoReachableAuthority,
                    $"No response from name servers for {question} at delegation {head.ZoneCut}.");

                cache.CacheResponse(failure);
                return (failure, null);
            }

            if (head.LastException is DnsClientResponseDnssecValidationException dnssecEx)
            {
                if (ede.Count > 0)
                    dnssecEx.Response.AddDnsClientExtendedError(ede);

                cache.CacheResponse(dnssecEx.Response, isDnssecBadCache: true);

                // qname mismatch → also cache synthesized failure
                if (dnssecEx.Response.Question.Count == 0 ||
                    !dnssecEx.Response.Question[0].Equals(question))
                {
                    var failure = MakeBaseFailure();
                    failure.AddDnsClientExtendedErrorFrom(dnssecEx.Response);
                    cache.CacheResponse(failure);
                }

                return (null, head.LastException);
            }

            if (head.LastException is DnsClientNoResponseException)
            {
                var failure = MakeBaseFailure();
                failure.AddDnsClientExtendedError(
                    EDnsExtendedDnsErrorCode.NoReachableAuthority,
                    $"No response from name servers for {question} at delegation {head.ZoneCut}.");

                cache.CacheResponse(failure);
                return (failure, null);
            }

            if (head.LastException is SocketException se)
            {
                var failure = MakeBaseFailure();

                if (se.SocketErrorCode == SocketError.TimedOut)
                {
                    failure.AddDnsClientExtendedError(
                        EDnsExtendedDnsErrorCode.NoReachableAuthority,
                        $"Request timed out for {question} at delegation {head.ZoneCut}.");
                }
                else
                {
                    failure.AddDnsClientExtendedError(
                        EDnsExtendedDnsErrorCode.NetworkError,
                        $"Socket error for {question}: {se.SocketErrorCode}");
                }

                cache.CacheResponse(failure);
                return (failure, null);
            }

            if (head.LastException is IOException ioe)
            {
                var failure = MakeBaseFailure();

                if (ioe.InnerException is SocketException se2)
                {
                    if (se2.SocketErrorCode == SocketError.TimedOut)
                    {
                        failure.AddDnsClientExtendedError(
                            EDnsExtendedDnsErrorCode.NoReachableAuthority,
                            $"Request timed out for {question} at delegation {head.ZoneCut}.");
                    }
                    else
                    {
                        failure.AddDnsClientExtendedError(
                            EDnsExtendedDnsErrorCode.NetworkError,
                            $"Socket error for {question}: {se2.SocketErrorCode}");
                    }
                }
                else
                {
                    failure.AddDnsClientExtendedError(
                        EDnsExtendedDnsErrorCode.NetworkError,
                        $"IO error for {question}: {ioe.Message}");
                }

                cache.CacheResponse(failure);
                return (failure, null);
            }

            // Generic resolver exception
            {
                var failure = MakeBaseFailure();

                failure.AddDnsClientExtendedError(
                    EDnsExtendedDnsErrorCode.Other,
                    $"Resolver exception for {question}: {head.LastException.Message}");

                cache.CacheResponse(failure);
                return (failure, null);
            }
        }

        private static DnsDatagram BuildDsFailure(
    DnsQuestionRecord lastQuestion,
    InternalState head,
    IDnsCache cache,
    List<EDnsExtendedDnsErrorOptionData> extendedDnsErrors,
    NetworkAddress? eDnsClientSubnet)
        {
            // Create SERVFAIL response for the original question
            var failure = new DnsDatagram(
                0,
                true,
                DnsOpcode.StandardQuery,
                false,
                false,
                false,
                false,
                false,
                false,
                DnsResponseCode.ServerFailure,
                new[] { lastQuestion }
            );

            //
            // Propagate accumulated EDE metadata, if any
            //
            if (extendedDnsErrors.Count > 0)
                failure.AddDnsClientExtendedError(extendedDnsErrors);

            //
            // Add DNSSEC-indeterminate EDE used in the DS unwind branch:
            //
            //  "Attack detected! Unable to resolve DS for <owner>"
            //
            failure.AddDnsClientExtendedError(
                EDnsExtendedDnsErrorCode.DnssecIndeterminate,
                $"Attack detected! Unable to resolve DS for {lastQuestion.Name.ToLowerInvariant()}"
            );

            //
            // Preserve ECS shadow data when present
            //
            if (eDnsClientSubnet is not null)
            {
                failure.SetShadowEDnsClientSubnetOption(
                    new EDnsClientSubnetOptionData(
                        eDnsClientSubnet.PrefixLength,
                        eDnsClientSubnet.PrefixLength,
                        eDnsClientSubnet.Address
                    )
                );
            }

            //
            // Cache as failure (same as current DS unwind behavior)
            //
            cache.CacheResponse(failure);

            return failure;
        }


        private static DnsDatagram GetMinimalResponseWithoutNSAndGlue(DnsDatagram full)
        {
            // Preserve the wire-level header + protocol flags exactly as-is
            var minimal = new DnsDatagram(ID: full.Identifier,
                                          isResponse: full.IsResponse,
                                          OPCODE: full.OPCODE,
                                          authoritativeAnswer: full.AuthoritativeAnswer,
                                          truncation: full.Truncation,
                                          recursionDesired: full.RecursionDesired,
                                          recursionAvailable: full.RecursionAvailable,
                                          authenticData: full.AuthenticData,
                                          checkingDisabled: full.CheckingDisabled,
                                          RCODE: full.RCODE,
                                          question: full.Question,
                                          answer: null,
                                          authority: null,
                                          additional: full.Additional,
                                          ednsFlags: full.EDNS.Flags,
                                          options: full.EDNS.Options);

            return minimal;
        }

    }
}
