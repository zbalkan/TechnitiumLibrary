/*
Technitium Library
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;


namespace TechnitiumLibrary.Net.Dns
{
    internal sealed class NameServerIterator
    {
        private readonly QueryContext _ctx;
        private readonly bool _preferIPv6;

        // Security limits
        private const int MAX_FAILURES_PER_SERVER = 3;
        private const int MAX_RETRIES_PER_AUTHORITY = 12;

        // Failure classification bucket
        private readonly Dictionary<NameServerAddress, FailureState> _failures =
            new Dictionary<NameServerAddress, FailureState>();

        private readonly IReadOnlyList<NameServerAddress> _ordered;
        private int _retryCount;

        public int ReferralLimit { get; }

        private sealed class FailureState
        {
            public int TimeoutFailures;
            public int BogusFailures;
            public int InsecureFailures;

            public int Total => TimeoutFailures + BogusFailures + InsecureFailures;
        }

        public NameServerIterator(QueryContext ctx, bool preferIPv6)
        {
            _ctx = ctx;
            _preferIPv6 = preferIPv6;

            var servers = _ctx.Head.NameServers ??
                throw new InvalidOperationException("No nameservers initialized.");

            ReferralLimit = Math.Min(
                servers.Count,
                DnsClient.MAX_NS_TO_QUERY_PER_REFERRAL);

            // Randomize initial ordering — but only once
            var shuffled = servers
                .Take(ReferralLimit)
                .OrderBy(_ => Guid.NewGuid())
                .ToList();

            // Light IPv6 preference without deterministic stickiness
            if (_preferIPv6)
                shuffled.Sort((a, b) =>
                    a.IPEndPoint?.AddressFamily.CompareTo(
                    b.IPEndPoint?.AddressFamily) ?? 0);

            _ordered = shuffled;
            _ctx.Head.NameServerIndex = 0;
        }

        public bool HasMore()
        {
            if (_retryCount >= MAX_RETRIES_PER_AUTHORITY)
                return false;

            return _ctx.Head.NameServerIndex < ReferralLimit;
        }

        /// <summary>
        /// Selects either:
        ///  • a batch of already-resolved nameservers (for concurrent querying)
        ///  • or a single unresolved nameserver that requires glue lookup
        /// </summary>
        public NameServerSelection SelectNextBatch()
        {
            if (!HasMore())
                return NameServerSelection.Unresolved(null!);

            int start = _ctx.Head.NameServerIndex;
            var batch = new List<NameServerAddress>();

            for (int i = start; i < ReferralLimit; i++)
            {
                var ns = _ordered[i];

                // Skip endpoints that repeatedly fail
                if (IsSuppressed(ns))
                    continue;

                if (ns.IPEndPoint is null)
                    break;

                batch.Add(ns);
            }

            if (batch.Count > 0)
            {
                _ctx.Head.NameServerIndex += batch.Count - 1;
                return NameServerSelection.ResolvedBatch(batch);
            }

            var single = _ordered[_ctx.Head.NameServerIndex];
            return NameServerSelection.Unresolved(single);
        }

        public void RecordTimeout(NameServerAddress ns) =>
            IncrementFailure(ns, f => f.TimeoutFailures++);

        public void RecordBogus(NameServerAddress ns) =>
            IncrementFailure(ns, f => f.BogusFailures++);

        public void RecordInsecure(NameServerAddress ns) =>
            IncrementFailure(ns, f => f.InsecureFailures++);

        private void IncrementFailure(
            NameServerAddress ns,
            Action<FailureState> apply)
        {
            if (!_failures.TryGetValue(ns, out var state))
                state = _failures[ns] = new FailureState();

            apply(state);

            _retryCount++;

            if (state.Total == MAX_FAILURES_PER_SERVER)
            {
                Trace.TraceWarning(
                    $"NameServerIterator suppressing {ns} after {state.Total} failures");
            }

            if (_retryCount == (int)(MAX_RETRIES_PER_AUTHORITY * 0.75))
            {
                Trace.TraceWarning(
                    $"Authority retry threshold approaching: {_retryCount}/{MAX_RETRIES_PER_AUTHORITY}");
            }
        }

        private bool IsSuppressed(NameServerAddress ns)
        {
            if (!_failures.TryGetValue(ns, out var f))
                return false;

            return f.Total >= MAX_FAILURES_PER_SERVER;
        }

        /// <summary>
        /// Used when retrying the same server after QNAME-minimization toggle.
        /// </summary>
        public void RewindToCurrent()
        {
            _ctx.Head.NameServerIndex--;
        }

        public void MoveNext()
        {
            _ctx.Head.NameServerIndex++;
        }
    }

    /// <summary>
    /// Represents the selection decision computed by the iterator.
    /// </summary>
    internal readonly struct NameServerSelection
    {
        public bool RequiresGlueResolution { get; }
        public IReadOnlyList<NameServerAddress>? Batch { get; }
        public NameServerAddress? Single { get; }

        private NameServerSelection(bool requiresGlue, IReadOnlyList<NameServerAddress>? batch, NameServerAddress? single)
        {
            RequiresGlueResolution = requiresGlue;
            Batch = batch;
            Single = single;
        }

        public static NameServerSelection ResolvedBatch(IReadOnlyList<NameServerAddress> servers) =>
            new NameServerSelection(false, servers, null);

        public static NameServerSelection Unresolved(NameServerAddress server) =>
            new NameServerSelection(true, null, server);
    }

}