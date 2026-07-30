/*
Technitium Library
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)
*/

using System;
using System.Collections.Generic;
using System.IO;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Dns.Dnssec
{
    /// <summary>Describes an active, temporary DNSSEC negative trust anchor.</summary>
    /// <param name="Name">
    /// Canonical ASCII, lower-case owner name without a trailing dot. The empty name is the root
    /// zone; see deviation D1 on <see cref="INegativeTrustAnchorProvider"/>.
    /// </param>
    /// <param name="ExpiresOnUtc">The absolute time at which the anchor expires.</param>
    public sealed record NegativeTrustAnchorInfo(string Name, DateTimeOffset ExpiresOnUtc)
    {
        /// <summary>
        /// Applies the resolver's own name rules to an operator-supplied anchor name, yielding the
        /// canonical form the resolver will actually enforce.
        /// </summary>
        /// <param name="name">A name as typed by an operator, e.g. <c>EXAMPLE.COM.</c> or <c>.</c>.</param>
        /// <param name="canonicalName">
        /// Lower-case A-label form with no trailing dot; the empty string for the root zone.
        /// </param>
        /// <returns><see langword="false"/> when the name cannot be used as an anchor at all.</returns>
        /// <remarks>
        /// Exposed so an application can normalize and reject at the point the operator enters a
        /// name, rather than storing it verbatim and discovering later that the resolver
        /// canonicalized it to something else or discarded it. Without this the configuration UI
        /// and the enforcement point can disagree about which names are anchored, and an unusable
        /// name simply never takes effect with nothing to show for it. Store the canonical form.
        /// </remarks>
        public static bool TryCanonicalizeName(string name, out string canonicalName)
        {
            canonicalName = DnsClient.CanonicalizeNegativeTrustAnchorNameOrNull(name);
            return canonicalName is not null;
        }
    }

    internal static class NegativeTrustAnchorInfoExtensions
    {
        /// <summary>
        /// Determines whether an NTA owner name covers a domain name, i.e. the name is the anchor
        /// itself or sits beneath it in the tree.
        /// </summary>
        /// <remarks>
        /// This is the single definition of NTA coverage. Every site that needs it must use this
        /// rather than open-coding a suffix test, because the root zone is the empty name and a
        /// literal <c>EndsWith("." + anchorName)</c> silently fails to match anything against it.
        /// Two such tests previously shipped, one of which suppressed the RFC 7646 section 5
        /// positive-trust-anchor restart below a root anchor.
        /// </remarks>
        internal static bool IsNameCoveredByAnchorName(string domainName, string anchorName)
        {
            if ((domainName is null) || (anchorName is null))
                return false;

            if (anchorName.Length == 0)
                return true; //root zone anchor covers the entire namespace

            return domainName.Equals(anchorName, StringComparison.OrdinalIgnoreCase) ||
                domainName.EndsWith("." + anchorName, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Writes an anchor's cache encoding: owner name, then expiry as UTC ticks.
        /// </summary>
        /// <remarks>
        /// Shared by the record and special-cache-record formats, which each embed this pair -
        /// once for a single anchor, once per entry in a counted list. Keeping one encoder and one
        /// decoder means the two formats cannot drift into disagreeing about the pair's layout.
        /// </remarks>
        internal static void WriteCacheEncodingTo(this NegativeTrustAnchorInfo anchor, BinaryWriter bW)
        {
            bW.Write(anchor.Name);
            bW.Write(anchor.ExpiresOnUtc.UtcDateTime.Ticks);
        }

        /// <summary>Reads the encoding written by <see cref="WriteCacheEncodingTo"/>.</summary>
        internal static NegativeTrustAnchorInfo ReadCacheEncodingFrom(BinaryReader bR)
        {
            string name = bR.ReadString();
            return new NegativeTrustAnchorInfo(name, new DateTimeOffset(bR.ReadInt64(), TimeSpan.Zero));
        }

        internal static NegativeTrustAnchorInfo MergeMostRestrictive(this NegativeTrustAnchorInfo existing, NegativeTrustAnchorInfo candidate)
        {
            if (existing is null)
                return candidate;
            if (candidate is null)
                return existing;
            if (!existing.Name.Equals(candidate.Name, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Negative trust anchor names do not match.", nameof(candidate));
            return existing.ExpiresOnUtc <= candidate.ExpiresOnUtc ? existing : candidate;
        }

        internal static bool RepresentsDependency(this NegativeTrustAnchorInfo retained, NegativeTrustAnchorInfo dependency)
        {
            return (retained is not null) && (dependency is not null) &&
                retained.Name.Equals(dependency.Name, StringComparison.OrdinalIgnoreCase) &&
                (retained.ExpiresOnUtc <= dependency.ExpiresOnUtc);
        }
    }

    /// <summary>
    /// How much detail an emitted EDE 33 option discloses in its EXTRA-TEXT field.
    /// </summary>
    /// <remarks>
    /// The structured form names the anchor and states when it expires. The anchor name can be
    /// broader than the name the client asked about, and the expiry tells any observer how long
    /// the validation bypass has left to run, so disclosure is a deliberate operator choice rather
    /// than a default. See deviation D6 on <see cref="INegativeTrustAnchorProvider"/>.
    /// </remarks>
    public enum NegativeTrustAnchorExtraTextMode
    {
        /// <summary>
        /// Emit a bare option with zero-length EXTRA-TEXT, disclosing only that an anchor applied.
        /// RFC 8914 section 2 permits this, and it is what the reference implementation emits.
        /// </summary>
        None = 0,

        /// <summary>
        /// Emit the draft's structured object - <c>{"d":"&lt;anchor&gt;","t":"&lt;RFC 3339 expiry&gt;"}</c>
        /// - using the JSON names the draft registers for this field.
        /// </summary>
        Structured = 1
    }

    /// <summary>Library-owned DNSSEC validation metadata for cache implementations.</summary>
    public sealed record DnssecCacheMetadata(
        DnssecStatus Status,
        NegativeTrustAnchorInfo AppliedNegativeTrustAnchor);

    /// <summary>
    /// Supplies the negative trust anchors currently configured by the operator. Implementations
    /// must be thread-safe, synchronous and non-blocking; the resolver calls this once at the
    /// start of a logical resolution and uses its own immutable copy thereafter.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Caller obligations.</b> A negative trust anchor suspends DNSSEC validation for a
    /// subtree, so the surrounding lifecycle is security-relevant and is deliberately not
    /// implemented here - the library has no operator interface, no persistence, no scheduler and
    /// no authority to evict another component's cache. Implementations of this interface own:
    /// </para>
    ///
    /// <list type="number">
    /// <item>Capping anchor lifetime. RFC 7646 section 5: the lifetime "SHOULD NOT exceed a
    /// week".</item>
    /// <item>Periodically retrying validation while an anchor is active, and removing the anchor
    /// once validation succeeds (RFC 7646 section 5).</item>
    /// <item>Flushing cached entries at and below the anchor node whenever an anchor is added or
    /// removed. RFC 7646 section 5 requires this on removal; it is equally necessary on addition,
    /// since already-cached secure records are otherwise unaffected until their TTL expires.
    /// Anchor <i>expiry</i> needs no flush, but only because the cache refuses to serve a record
    /// carrying an expired anchor. <see cref="DnsCache"/> does that on its read paths; an
    /// <see cref="IDnsCache"/> implementation that supplies its own read path owns the check, or a
    /// record admitted solely because validation was suspended outlives the anchor that
    /// permitted it.</item>
    /// <item>Deciding whether an EDE 33 diagnostic reaches clients, and how verbose it is. The
    /// library records provenance and exposes a generator; it never emits on its own.</item>
    /// </list>
    ///
    /// <para>
    /// <b>Documented deviations.</b> Where this implementation departs from RFC 7646, RFC 8914 or
    /// draft-farrokhi-dnsop-ede-nta, the departure is deliberate and recorded here. Each site that
    /// implements one carries a comment referring back to its identifier. Pragmatic choices are
    /// allowed; undocumented ones are not.
    /// </para>
    ///
    /// <list type="bullet">
    /// <item><b>D1 - root zone anchors are accepted.</b> RFC 7646 section 5 says an NTA "SHOULD be
    /// used only in a specific domain or sub-domain". An anchor at the root is therefore
    /// discouraged, and it suspends validation for the entire namespace. It is nonetheless
    /// accepted, matching the reference implementation of the EDE draft (PowerDNS Recursor, which
    /// supports and tests a root NTA): the alternative was to discard an explicitly configured
    /// anchor, which previously happened silently and left the operator with neither an active NTA
    /// nor any indication of why. Honouring explicit configuration is less surprising than
    /// ignoring it. The RFC's accompanying MUST - that an NTA "MUST NOT affect validation of other
    /// names up the authentication chain" - is not violated, because the root has no names above
    /// it.</item>
    ///
    /// <item><b>D2 - the EDE is emitted on causation, not coverage.</b> The draft permits a
    /// resolver to emit EDE 33 "on any responses while an NTA is in effect, regardless of whether
    /// the presence of the NTA had a material effect". This implementation emits only where an NTA
    /// actually demoted a chain that would otherwise have validated, which is a strict subset of
    /// what the draft allows and therefore conformant, but narrower than the reference
    /// implementation. A name that was already insecure for an unrelated reason and merely happens
    /// to sit under an NTA produces no EDE here, where PowerDNS produces one.</item>
    ///
    /// <item><b>D3 - emission is off unless the application asks for it.</b> The draft says an
    /// operator applying an NTA "SHOULD return this EDE in affected responses". This library never
    /// emits on its own. The reference implementation reached the same position, shipping the
    /// feature disabled by default. Satisfying the draft's SHOULD is consequently a deployment
    /// responsibility, not a library guarantee.</item>
    ///
    /// <item><b>D4 - anchor lifetime is not capped.</b> RFC 7646 section 5 says an NTA lifetime
    /// "SHOULD NOT exceed a week". Anchor names are validated and canonicalized at capture but
    /// expiry is not, since the acceptable ceiling is operator policy. See caller obligation 1
    /// above.</item>
    ///
    /// <item><b>D5 - cache invalidation is delegated.</b> RFC 7646 section 5 says that when
    /// removing an NTA "the implementation SHOULD remove all cached entries at and below the NTA
    /// node". A library cache cannot know when operator policy changed. See caller obligation 3
    /// above. An earlier revision carried a policy-generation stamp on every cached record to
    /// enforce this in-library; it was removed because it cost roughly 800 lines, invalidated the
    /// whole cache rather than the affected subtree, and duplicated a remedy the RFC already
    /// assigns to the operator.</item>
    ///
    /// <item><b>D6 - EXTRA-TEXT carries structured data.</b> RFC 8914 section 2 describes
    /// EXTRA-TEXT as "intended for human consumption (not automated parsing)". The draft
    /// nonetheless registers the JSON names "d" and "t" for exactly this field, so the structured
    /// form is available when the application requests it. The root zone is rendered as "." rather
    /// than the empty string the draft's "no trailing period" rule would imply, because an empty
    /// "d" is not a usable domain name representation for a consumer.</item>
    /// </list>
    /// </remarks>
    public interface INegativeTrustAnchorProvider
    {
        /// <summary>
        /// Returns the negative trust anchors currently in force. Called once per logical
        /// resolution; the returned collection is copied immediately and never retained.
        /// </summary>
        IReadOnlyCollection<NegativeTrustAnchorInfo> GetActiveAnchors();
    }

    /// <summary>
    /// An immutable, canonicalized set of negative trust anchors with most-specific-match lookup.
    /// </summary>
    /// <remarks>
    /// The resolver never consults an <see cref="INegativeTrustAnchorProvider"/> directly beyond
    /// the single call that builds this set. A provider's collection may be backed by live,
    /// mutable state, and a validation decision that changed midway through one resolution could
    /// leave a partially-validated chain, so the anchors are copied, canonicalized and frozen up
    /// front. Canonicalization also merges duplicate owner names to the earliest expiry, so the
    /// effective lifetime cannot depend on enumeration order.
    /// </remarks>
    internal sealed class NegativeTrustAnchorSet
    {
        public static readonly NegativeTrustAnchorSet Empty = new NegativeTrustAnchorSet(new Dictionary<string, NegativeTrustAnchorInfo>(StringComparer.OrdinalIgnoreCase));

        readonly Dictionary<string, NegativeTrustAnchorInfo> _anchorsByName;
        readonly IReadOnlyList<NegativeTrustAnchorInfo> _anchors;

        private NegativeTrustAnchorSet(Dictionary<string, NegativeTrustAnchorInfo> anchorsByName)
        {
            _anchorsByName = anchorsByName;

            NegativeTrustAnchorInfo[] anchors = new NegativeTrustAnchorInfo[anchorsByName.Count];
            anchorsByName.Values.CopyTo(anchors, 0);
            _anchors = Array.AsReadOnly(anchors);
        }

        /// <summary>
        /// Copies, canonicalizes and freezes the anchors a provider reports. A provider that
        /// throws, or an anchor whose name cannot be canonicalized, yields no anchor rather than
        /// an error: an unusable NTA leaves validation enabled, which is the fail-closed outcome.
        /// </summary>
        public static NegativeTrustAnchorSet Capture(INegativeTrustAnchorProvider provider, Func<string, string> canonicalize)
        {
            if (provider is null)
                return Empty;

            IReadOnlyCollection<NegativeTrustAnchorInfo> reported;
            try
            {
                reported = provider.GetActiveAnchors();
            }
            catch
            {
                return Empty; //NTA policy must not become a DNS availability dependency
            }

            if ((reported is null) || (reported.Count == 0))
                return Empty;

            Dictionary<string, NegativeTrustAnchorInfo> anchors = new Dictionary<string, NegativeTrustAnchorInfo>(StringComparer.OrdinalIgnoreCase);

            foreach (NegativeTrustAnchorInfo anchor in reported)
            {
                if ((anchor is null) || (anchor.Name is null))
                    continue;

                string canonicalName = canonicalize(anchor.Name);
                if (canonicalName is null)
                    continue;

                NegativeTrustAnchorInfo canonicalAnchor = canonicalName.Equals(anchor.Name, StringComparison.Ordinal) ? anchor : new NegativeTrustAnchorInfo(canonicalName, anchor.ExpiresOnUtc);

                anchors[canonicalName] = anchors.TryGetValue(canonicalName, out NegativeTrustAnchorInfo existing) ? existing.MergeMostRestrictive(canonicalAnchor) : canonicalAnchor;
            }

            return anchors.Count == 0 ? Empty : new NegativeTrustAnchorSet(anchors);
        }

        public int Count
        { get { return _anchors.Count; } }

        public IReadOnlyList<NegativeTrustAnchorInfo> Anchors
        { get { return _anchors; } }

        /// <summary>Finds the most specific anchor covering a name, if any.</summary>
        /// <remarks>
        /// Walks the name up to the root one label at a time, probing the anchor map at each node,
        /// so the cost is the label count of the query name - typically three to five lookups -
        /// rather than the size of the anchor set. The previous implementation scanned every
        /// anchor and built a <c>"." + name</c> string per candidate, on the hot path at every zone
        /// cut; with a large anchor set that dominated. Walking upwards also yields the
        /// most-specific match by construction, with the root (the empty name) probed last, so no
        /// name-length comparison is needed to break ties.
        /// </remarks>
        public bool TryGetCoveringAnchor(string domainName, out NegativeTrustAnchorInfo anchor)
        {
            anchor = null;

            if (domainName is null)
                return false;

            string node = domainName;

            while (true)
            {
                if (_anchorsByName.TryGetValue(node, out anchor))
                    return true;

                if (node.Length == 0)
                    return false; //the root was the last node to test

                int separator = node.IndexOf('.');
                node = (separator < 0) ? "" : node.Substring(separator + 1);
            }
        }
    }
}
