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
    /// application. If callers could freely construct one, they could pair an arbitrary set of
    /// trust anchors with a <see cref="DnsCacheWriteContext"/> captured for a different, unrelated
    /// policy - letting results produced under one trust policy be stamped with another policy's
    /// cache identity and read or populate its cache entries. Keeping construction internal to
    /// this library removes that path entirely, so <see cref="GetDnssecResolutionPolicySnapshot"/>
    /// never needs to distrust an <see cref="DnssecEffectivePolicy"/> instance it is handed - by
    /// construction, one only ever exists because this library captured it coherently.
    /// </remarks>
    public sealed class DnssecEffectivePolicy
    {
        internal DnssecEffectivePolicy(DnsCacheWriteContext cacheContext, INegativeTrustAnchorSnapshot negativeTrustAnchors, IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecord>> positiveTrustAnchors, IReadOnlyList<DnsResourceRecord> rootTrustAnchors)
        {
            CacheContext = cacheContext;
            NegativeTrustAnchors = negativeTrustAnchors;
            PositiveTrustAnchors = positiveTrustAnchors;
            RootTrustAnchors = rootTrustAnchors;
        }

        public DnsCacheWriteContext CacheContext { get; }
        public INegativeTrustAnchorSnapshot NegativeTrustAnchors { get; }
        public IReadOnlyDictionary<string, IReadOnlyList<DnsResourceRecord>> PositiveTrustAnchors { get; }
        public IReadOnlyList<DnsResourceRecord> RootTrustAnchors { get; }
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

        bool TryGetCoveringAnchor(string domainName, out NegativeTrustAnchorInfo anchor);
    }
}
