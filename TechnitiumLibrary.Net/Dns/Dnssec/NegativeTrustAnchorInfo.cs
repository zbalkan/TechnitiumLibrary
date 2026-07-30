/*
Technitium Library
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)
*/

using System;
using System.Collections.Generic;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Dns.Dnssec
{
    /// <summary>Describes an active, temporary DNSSEC negative trust anchor.</summary>
    /// <param name="Name">Canonical ASCII, lower-case owner name without a trailing dot.</param>
    /// <param name="ExpiresOnUtc">The absolute time at which the anchor expires.</param>
    public sealed record NegativeTrustAnchorInfo(string Name, DateTimeOffset ExpiresOnUtc);

    internal static class NegativeTrustAnchorInfoExtensions
    {
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

    /// <summary>Library-owned DNSSEC validation metadata for cache implementations.</summary>
    public sealed record DnssecCacheMetadata(
        DnssecStatus Status,
        NegativeTrustAnchorInfo AppliedNegativeTrustAnchor,
        DnsCacheWriteContext DnsCacheWriteContext = null);

    /// <summary>
    /// Supplies active negative trust anchors to DNSSEC validation. Implementations must be
    /// thread-safe, synchronous, non-blocking, and return the most-specific covering anchor.
    /// </summary>
    /// <remarks>
    /// Use <see cref="IDnssecTrustPolicyProvider"/> instead when positive trust anchors and NTAs
    /// may coexist so both policy components are captured atomically.
    ///
    /// Changing active anchors does not invalidate resolver state. Callers must invalidate
    /// affected positive, negative, DNSSEC failure, DS, DNSKEY, and delegation cache entries.
    /// Invalidation must also prevent resolutions captured under an older policy generation from
    /// repopulating the cache after the policy change.
    /// </remarks>
    public interface INegativeTrustAnchorProvider
    {
        /// <summary>Captures one immutable policy view for a logical resolution.</summary>
        INegativeTrustAnchorSnapshot CaptureSnapshot();
    }

    /// <summary>Atomically supplies positive and negative DNSSEC trust policy.</summary>
    public interface IDnssecTrustPolicyProvider
    {
        /// <summary>Captures one immutable policy generation for a complete logical resolution.</summary>
        DnssecTrustPolicySnapshot CaptureSnapshot();
    }

    public sealed record DnssecTrustPolicySnapshot(
        long Generation,
        DateTimeOffset CapturedOnUtc,
        INegativeTrustAnchorSnapshot NegativeTrustAnchors,
        IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecord>> PositiveTrustAnchors,
        Guid PolicyScopeId,
        Guid PolicyRevisionId);

    /// <summary>
    /// An immutable, resolver-ready DNSSEC policy view shared with cache enforcement.
    /// </summary>
    /// <remarks>
    /// This type is deliberately opaque: it can only be produced by
    /// <see cref="DnsClient.CaptureDnssecPolicy"/>, never constructed directly by a consuming
    /// application, and it exposes no accessor to the trust anchor material it wraps. An earlier
    /// revision exposed <c>PositiveTrustAnchors</c>/<c>RootTrustAnchors</c> as public properties;
    /// since those were the exact <see cref="Dictionary{TKey,TValue}"/> and array-backed
    /// <see cref="IReadOnlyList{T}"/> instances used internally, a caller could downcast and
    /// mutate them (or mutate a <c>DsRecordData.Digest</c> byte array reachable from
    /// <c>RootTrustAnchors</c>) after capture, then hand the same object back for reuse - so the
    /// resolver would use the tampered trust material while still reporting the original,
    /// unrelated cache revision. Keeping the captured <see cref="DnsClient.DnssecResolutionPolicySnapshot"/>
    /// entirely private, with no public path back to it, removes that mutation channel: the only
    /// party that can ever read the wrapped trust anchors is this library's own resolution code,
    /// via <see cref="Snapshot"/>, which is <see langword="internal"/>.
    /// </remarks>
    public sealed class DnssecEffectivePolicy
    {
        readonly DnsClient.DnssecResolutionPolicySnapshot _snapshot;

        internal DnssecEffectivePolicy(DnsClient.DnssecResolutionPolicySnapshot snapshot)
        {
            _snapshot = snapshot;
        }

        /// <summary>Gets the library-private snapshot this policy wraps. Never exposed publicly.</summary>
        internal DnsClient.DnssecResolutionPolicySnapshot Snapshot
        { get { return _snapshot; } }

        /// <summary>Gets the cache write context identifying this policy for cache enforcement.</summary>
        public DnsCacheWriteContext CacheContext
        { get { return new DnsCacheWriteContext(_snapshot.Generation, _snapshot.CapturedOnUtc, _snapshot.PolicyScopeId, _snapshot.PolicyRevisionId); } }
    }

    public interface INegativeTrustAnchorSnapshot
    {
        /// <summary>Gets the stable identity of the policy domain that produced this snapshot.</summary>
        Guid PolicyScopeId { get; }

        /// <summary>Gets the immutable identity of the policy semantics represented by this snapshot.</summary>
        Guid PolicyRevisionId { get; }

        /// <summary>Gets the application-defined policy generation represented by this snapshot.</summary>
        long Generation { get; }

        /// <summary>Gets the instant at which this immutable policy view was captured.</summary>
        DateTimeOffset CapturedOnUtc { get; }

        /// <summary>
        /// Gets every negative trust anchor active in this snapshot. The resolver reads this once,
        /// at capture time, to build its own frozen copy of the policy - implementations must
        /// return a view that reflects only the anchors active at <see cref="CapturedOnUtc"/> and
        /// must not change what it yields afterward.
        /// </summary>
        IReadOnlyCollection<NegativeTrustAnchorInfo> Anchors { get; }

        bool TryGetCoveringAnchor(string domainName, out NegativeTrustAnchorInfo anchor);
    }

    /// <summary>
    /// A library-owned, immutable negative trust anchor snapshot built by copying every anchor out
    /// of an externally supplied <see cref="INegativeTrustAnchorSnapshot"/> at capture time.
    /// </summary>
    /// <remarks>
    /// An external provider's own snapshot object could be backed by a live, mutable collection
    /// that continues to change after capture even though the provider contract calls the
    /// snapshot immutable - the resolver has no way to enforce that promise on an object it does
    /// not own. Materializing <see cref="INegativeTrustAnchorSnapshot.Anchors"/> into this frozen
    /// wrapper once, at capture, and never touching the original object again closes that gap: the
    /// resolver's entire view of active anchors for one logical resolution is fixed at capture
    /// time, matching the guarantee the cache scope/revision/generation identity already implies.
    /// </remarks>
    internal sealed class FrozenNegativeTrustAnchorSnapshot : INegativeTrustAnchorSnapshot
    {
        readonly IReadOnlyList<NegativeTrustAnchorInfo> _anchors;

        public FrozenNegativeTrustAnchorSnapshot(Guid policyScopeId, Guid policyRevisionId, long generation, DateTimeOffset capturedOnUtc, IReadOnlyList<NegativeTrustAnchorInfo> anchors)
        {
            PolicyScopeId = policyScopeId;
            PolicyRevisionId = policyRevisionId;
            Generation = generation;
            CapturedOnUtc = capturedOnUtc;
            _anchors = anchors;
        }

        public Guid PolicyScopeId { get; }

        public Guid PolicyRevisionId { get; }

        public long Generation { get; }

        public DateTimeOffset CapturedOnUtc { get; }

        public IReadOnlyCollection<NegativeTrustAnchorInfo> Anchors
        { get { return (IReadOnlyCollection<NegativeTrustAnchorInfo>)_anchors; } }

        public bool TryGetCoveringAnchor(string domainName, out NegativeTrustAnchorInfo anchor)
        {
            anchor = null;

            if (string.IsNullOrEmpty(domainName))
                return false;

            NegativeTrustAnchorInfo best = null;

            foreach (NegativeTrustAnchorInfo candidate in _anchors)
            {
                if ((candidate is null) || string.IsNullOrEmpty(candidate.Name))
                    continue;

                bool matches = domainName.Equals(candidate.Name, StringComparison.OrdinalIgnoreCase) ||
                    domainName.EndsWith("." + candidate.Name, StringComparison.OrdinalIgnoreCase);

                if (!matches)
                    continue;

                if ((best is null) || (candidate.Name.Length > best.Name.Length))
                    best = candidate;
            }

            if (best is null)
                return false;

            anchor = best;
            return true;
        }
    }
}
