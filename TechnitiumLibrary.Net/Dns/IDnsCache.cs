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
using System.Threading.Tasks;

namespace TechnitiumLibrary.Net.Dns
{

    public interface IDnsCache
    {
        /// <summary>Queries cached resolver data.</summary>
        /// <remarks>
        /// Implementations must restore resolver-local
        /// <see cref="DnsDatagram.AppliedNegativeTrustAnchors"/> provenance, and must not set AD
        /// when any returned answer or authority record was accepted under a negative trust anchor.
        ///
        /// <para>
        /// Implementations must not return an RRset or special response after any negative trust
        /// anchor used to accept that data has expired. Expiry is the only negative-trust-anchor
        /// invalidation the library performs; invalidation when the operator <i>adds or removes</i>
        /// an anchor belongs to the application, which must flush entries at and below the anchor
        /// node. See RFC 7646 section 4 and deviation D5 on
        /// <see cref="Dnssec.INegativeTrustAnchorProvider"/>.
        /// </para>
        /// </remarks>
        Task<DnsDatagram> QueryAsync(DnsDatagram request, bool serveStale = false, bool findClosestNameServers = false, bool resetExpiry = false);

        /// <summary>Caches a resolver response, including its negative trust anchor provenance.</summary>
        /// <remarks>
        /// Records accepted under a negative trust anchor carry that anchor as provenance. An
        /// implementation must preserve it, both so the anchor's expiry can be honoured on read
        /// and so the application can decide whether to disclose it to clients as EDE 33.
        /// </remarks>
        void CacheResponse(DnsDatagram response, bool isDnssecBadCache = false, string zoneCut = null);
    }
}
