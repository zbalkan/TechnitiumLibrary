using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Dns
{
    internal sealed class GlueResolutionCoordinator
    {
        private readonly QueryContext _ctx;
        private readonly bool _dnssecValidation;
        private readonly bool _preferIPv6;
        private readonly bool _asyncNsResolution;
        private readonly Dictionary<string, object>? _asyncTasks;

        public GlueResolutionCoordinator(
            QueryContext ctx,
            bool dnssecValidation,
            bool preferIPv6,
            bool asyncNsResolution,
            Dictionary<string, object>? asyncTasks)
        {
            _ctx = ctx;
            _dnssecValidation = dnssecValidation;
            _preferIPv6 = preferIPv6;
            _asyncNsResolution = asyncNsResolution;
            _asyncTasks = asyncTasks;
        }

        /// <summary>
        /// Pushes a child resolver frame to resolve glue (A/AAAA or DS)
        /// for the given NS hostname.
        /// </summary>
        public void PushGlueLookupFrame(
            NameServerAddress ns,
            DnsQuestionRecord originalQuestion)
        {
            var head = _ctx.Head;

            var rrType = _preferIPv6
                ? SelectRecordTypeWithIpv6Fallback(ns)
                : DnsResourceRecordType.A;

            var child = new InternalState
            {
                Question = new DnsQuestionRecord(
                    ns.DomainEndPoint.Address,
                    rrType,
                    DnsClass.IN),

                ZoneCut = head.ZoneCut,
                NameServers = new List<NameServerAddress> { ns },
                NameServerIndex = 0,

                DnssecValidationState = _dnssecValidation,
                LastDSRecords = head.LastDSRecords,
                HopCount = head.HopCount,

                LastResponse = null,
                LastException = null
            };

            // opportunistic async prefetch marker
            if (_asyncNsResolution && _asyncTasks is not null)
                _asyncTasks.TryAdd(ns.DomainEndPoint.Address.ToLowerInvariant(), null);

            // push current head and install child
            _ctx.Stack.Push(head);
            _ctx.Head = child;
        }

        /// <summary>
        /// Preserve legacy behavior:
        /// Prefer AAAA first when IPv6 is enabled,
        /// fall back to A if AAAA already attempted.
        /// </summary>
        private DnsResourceRecordType SelectRecordTypeWithIpv6Fallback(NameServerAddress ns)
        {
            bool attemptedAaaa = false;
            bool attemptedA = false;

            foreach (var prior in _ctx.Head.NameServers!)
            {
                if (!prior.DomainEndPoint.Address.Equals(
                        ns.DomainEndPoint.Address,
                        System.StringComparison.OrdinalIgnoreCase))
                    continue;

                if (prior.IPEndPoint is null)
                {
                    attemptedAaaa = true;
                    break;
                }

                switch (prior.IPEndPoint.AddressFamily)
                {
                    case AddressFamily.InterNetwork:
                        attemptedA = true;
                        break;

                    case AddressFamily.InterNetworkV6:
                        attemptedAaaa = true;
                        break;
                }
            }

            // if AAAA already failed → query A
            if (attemptedAaaa)
                return DnsResourceRecordType.A;

            // first attempt AAAA, ensure future A fallback exists
            if (!attemptedA)
                AddDeferredIpv4Fallback(ns);

            return DnsResourceRecordType.AAAA;
        }

        private void AddDeferredIpv4Fallback(NameServerAddress ns)
        {
            _ctx.Head.NameServers!.Add(ns.Clone((IPEndPoint?)null));

            if (_asyncNsResolution && _asyncTasks is not null)
                _asyncTasks.TryAdd(ns.DomainEndPoint.Address.ToLowerInvariant(), null);
        }
    }
}
