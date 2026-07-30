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
    public sealed record DnsCacheWriteContext(long DnssecPolicyGeneration, DateTimeOffset PolicyCapturedOnUtc, Guid PolicyScopeId, Guid PolicyRevisionId);

    public interface IDnsCache
    {
        /// <summary>Queries cached resolver data.</summary>
        /// <remarks>
        /// Implementations must restore resolver-local
        /// <see cref="DnsDatagram.AppliedNegativeTrustAnchors"/> provenance and must not set AD
        /// when any returned answer or authority record was accepted under a negative trust anchor.
        /// Implementations must not return an RRset or special response after any negative trust
        /// anchor used to accept that data has expired.
        /// When policy changes, consuming applications must also prevent in-flight resolutions
        /// captured under an older policy generation from repopulating invalidated cache data.
        /// When <see cref="DnsDatagram.DnsCacheWriteContext"/> is present on the request, every
        /// retained answer, authority, additional, and special cache record must have the same
        /// policy scope, immutable revision, and generation; otherwise the implementation must
        /// return a cache miss.
        /// </remarks>
        Task<DnsDatagram> QueryAsync(DnsDatagram request, bool serveStale = false, bool findClosestNameServers = false, bool resetExpiry = false);

        /// <summary>Caches a resolver response, including its negative trust anchor provenance.</summary>
        /// <remarks>
        /// Implementations that enforce mutable DNSSEC policy must compare
        /// <see cref="DnsDatagram.DnsCacheWriteContext"/> with the current application policy and
        /// reject writes whose policy scope, immutable revision, or generation is obsolete.
        /// Generation zero has no universal
        /// meaning and must be interpreted according to the consuming application's policy model.
        /// Generation enforcement applies to every resolver cache representation, including
        /// positive and negative answers, referrals, DS and DNSKEY data, failures, and DNSSEC bad
        /// cache entries. A cache which does not support mutable trust policy may accept all writes.
        /// </remarks>
        void CacheResponse(DnsDatagram response, bool isDnssecBadCache = false, string zoneCut = null);
    }
}
