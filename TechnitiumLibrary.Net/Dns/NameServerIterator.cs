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

namespace TechnitiumLibrary.Net.Dns
{
    internal sealed class NameServerIterator
    {
        private readonly QueryContext _ctx;
        private readonly bool _preferIPv6;

        public int ReferralLimit { get; private set; }

        public NameServerIterator(QueryContext ctx, bool preferIPv6)
        {
            _ctx = ctx;
            _preferIPv6 = preferIPv6;

            var servers = _ctx.Head.NameServers ?? throw new InvalidOperationException("No nameservers initialized.");

            ReferralLimit = Math.Min(
                servers.Count,
                DnsClient.MAX_NS_TO_QUERY_PER_REFERRAL);
        }

        public bool HasMore()
        {
            return _ctx.Head.NameServerIndex < ReferralLimit;
        }

        /// <summary>
        /// Selects either:
        ///  • a batch of already-resolved nameservers (for concurrent querying)
        ///  • or a single unresolved nameserver that requires glue lookup
        /// </summary>
        public NameServerSelection SelectNextBatch()
        {
            var servers = _ctx.Head.NameServers;

            int start = _ctx.Head.NameServerIndex;

            var resolved = new List<NameServerAddress>(
                ReferralLimit - start);

            // Build contiguous batch of already-resolved name servers
            for (int i = start; i < ReferralLimit; i++)
            {
                if (servers[i].IPEndPoint is null)
                    break;

                resolved.Add(servers[i]);
            }

            if (resolved.Count > 0)
            {
                // Skip these when returning to caller
                _ctx.Head.NameServerIndex += resolved.Count - 1;

                return NameServerSelection.ResolvedBatch(resolved);
            }

            // Otherwise return the current unresolved NS
            var current = servers[_ctx.Head.NameServerIndex];
            return NameServerSelection.Unresolved(current);
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