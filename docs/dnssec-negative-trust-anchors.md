# DNSSEC Negative Trust Anchors — integration guide for Technitium DNS Server

This document describes what TechnitiumLibrary provides for RFC 7646 Negative Trust Anchors (NTAs)
and the draft EDE 33 signal, and what Technitium DNS Server must implement to complete the feature.

The split is deliberate. A negative trust anchor **suspends DNSSEC validation** for a subtree, so
the enforcement point has to live inside the resolver loop — that is the library. Everything around
it (who may create an anchor, for how long, when the cache is flushed, whether clients are told) is
operator policy, and the library has no operator interface, no persistence, no scheduler, and no
authority to evict the server's cache.

**Specifications:** RFC 7646 (NTAs), RFC 8914 (Extended DNS Errors),
[draft-farrokhi-dnsop-ede-nta](https://datatracker.ietf.org/doc/draft-farrokhi-dnsop-ede-nta/) (EDE 33).

---

## 1. What the library does

- Applies negative trust anchor precedence at every zone cut, per RFC 7646 §2.1 and §3.
- Suspends validation for names covered by an active anchor, and clears the AD bit on affected
  responses, per RFC 7646 §1.1.
- Records **which** anchor caused a chain to be demoted, as provenance on the affected records and
  on the response, and preserves it across the cache.
- Rejects cached data once the anchor that justified accepting it has expired — *in `DnsCache`*.
  A cache that overrides the read path must enforce this itself; see §7.
- Formats the EDE 33 option on request. It never emits one on its own.

## 2. What the server must implement

These are enumerated in the XML documentation on `INegativeTrustAnchorProvider` and repeated here.

| # | Obligation | Source |
|---|---|---|
| 0 | **Migrate the resolve call sites** to `RecursiveResolveWithOptionsAsync`. The legacy overload cannot carry an anchor provider and fails silently | see §3 |
| 1 | **Store and manage anchors** — admin API/UI, persistence, listing. Normalize operator input with `NegativeTrustAnchorInfo.TryCanonicalizeName` and store the canonical form | — |
| 2 | **Cap anchor lifetime.** "The lifetime SHOULD NOT exceed a week" | RFC 7646 §4 |
| 3 | **Retry validation periodically** while an anchor is active, and remove it once validation succeeds | RFC 7646 §4 |
| 4 | **Flush cached entries at and below the anchor node** when an anchor is **added or removed** | RFC 7646 §4 |
| 5 | **Decide whether EDE 33 reaches clients**, and how verbose it is | draft §4 |
| 6 | **Suppress EDE 33 when the query was not subject to validation** | see §6 below |
| 7 | **Log anchor creation/removal**; consider disclosing active anchors to operators | RFC 7646 §3.1 |

Obligation 4 deserves emphasis. The RFC requires the flush on *removal*; it is equally necessary on
*addition*, because already-cached secure records are otherwise unaffected until their TTL expires
and the new anchor appears not to work.

Anchor **expiry** needs no flush — but only because the cache refuses to serve a record carrying an
expired anchor. `DnsCache` does that on its read paths; `CacheZoneManager` overrides those paths and
so owns the check itself. See §7, where this is currently listed as unimplemented.

## 3. Wiring it up

Implement the provider:

```csharp
sealed class ServerNegativeTrustAnchorProvider : INegativeTrustAnchorProvider
{
    // Called once per logical resolution. Must be thread-safe, synchronous and non-blocking.
    // The returned collection is copied immediately and never retained.
    public IReadOnlyCollection<NegativeTrustAnchorInfo> GetActiveAnchors()
    {
        // Names are canonicalized by the library; "." and "" both mean the root zone.
        return _anchors;   // e.g. an immutable snapshot of the operator's configured NTAs
    }
}
```

### Migrate the resolve call sites first

`DnsServer.cs:5027` and `:5354` currently call the legacy overload:

```csharp
await DnsClient.RecursiveResolveAsync(question, dnsCache, _proxy, ..., dnssecValidation, ...)
```

**That overload cannot carry trust policy.** It has no parameter for an anchor provider, so it
always resolves against the built-in root anchors — silently, with no error and no warning,
however the server's policy is configured. Until both call sites move to the options overload,
nothing else in this document has any effect.

Pass the provider in through `RecursiveResolveOptions`:

```csharp
RecursiveResolveOptions options = new RecursiveResolveOptions
{
    Cache = _cacheZoneManager,
    DnssecValidation = true,
    NegativeTrustAnchorProvider = _ntaProvider,
};

DnsDatagram response = await DnsClient.RecursiveResolveQueryWithOptionsAsync(question, options);
```

A provider that throws, or an anchor whose name cannot be canonicalized, yields **no anchor** rather
than an error. Validation stays enabled — the fail-closed outcome. NTA policy must never become a
DNS availability dependency.

## 4. Reading provenance

After resolution, `DnsDatagram.AppliedNegativeTrustAnchors` lists the anchors that actually demoted
this answer. This is the accessor to use for emission decisions.

Per-record provenance is reachable through `DnsResourceRecord.GetDnssecCacheMetadata()`, which
returns a `DnssecCacheMetadata(DnssecStatus Status, NegativeTrustAnchorInfo AppliedNegativeTrustAnchor)`.
The corresponding `CloneWithDnssecCacheMetadata(...)` reattaches it — together these are the public
surface a custom cache needs in order to round-trip provenance. The backing field itself is
`internal`; a cache must go through these two methods rather than expecting a settable property.

The anchor list is empty unless an NTA **caused** the insecure state. See deviation **D2** below.

## 5. Emitting EDE 33

```csharp
if (_settings.NegativeTrustAnchorExtendedError && queryWasSubjectToValidation)
{
    response.AddNegativeTrustAnchorExtendedDnsErrors(
        _settings.NegativeTrustAnchorExtendedErrorVerbose
            ? NegativeTrustAnchorExtraTextMode.Structured
            : NegativeTrustAnchorExtraTextMode.None);
}
```

`AddNegativeTrustAnchorExtendedDnsErrors(...)` adds EDE 33 options into
`DnsDatagram.DnsClientExtendedErrors`, which the server merges into the outgoing OPT record
alongside `response.EDNS.Options`. It is idempotent, and will not add an option that already exists
in the response's own EDNS options — so a diagnostic forwarded from upstream is not duplicated.

**Two decisions, both yours.**

*Whether to emit.* Recommended default **off**. PowerDNS Recursor ships this feature disabled by
default, and the draft's "SHOULD return this EDE" is a deployment decision (deviation **D3**).

*How much to disclose*, via `NegativeTrustAnchorExtraTextMode`:

| Mode | EXTRA-TEXT | Notes |
|------|-----------|-------|
| `None` (default) | empty | Discloses only that an anchor applied. RFC 8914 §2 permits zero-length; this is what PowerDNS emits. Several applied anchors collapse to a single bare option. |
| `Structured` | `{"d":"<anchor>","t":"<RFC 3339 expiry>"}` | The draft's registered JSON names. Each anchor yields a distinct option, satisfying the draft's requirement that EXTRA-TEXT be populated when multiple instances appear. |

`Structured` discloses the anchor name — which may be broader than the name the client asked about
— and when the validation bypass ends. Treat it as an opt-in for operators who want the detail.

## 6. The validation-gating hazard

Provenance is restored on cache hits **unconditionally**. If a validating client populates the cache
and a non-validating client then hits the same entry, that second response still carries the
provenance — and emitting EDE 33 for it would be wrong, because that query was never subject to
validation.

PowerDNS hit exactly this and needed a dedicated fix, adding `shouldValidate()` to their emission
condition. Because emission here is server-owned, the library cannot make this call for you.

**Guard your emission on whether *this* query was subject to validation** — which depends on the
server's DNSSEC mode and, in a process-style mode, on the client having set AD or DO.

## 7. Where the obligations land in the server

The resolver's counterparty is **not** `CacheZoneManager`. It is `ResolverDnsCache`, a facade:

```
DnsClient  →  ResolverDnsCache : IDnsCache        ← what RecursiveResolve* is handed
                 ├── AuthZoneManager              (authoritative data)
                 ├── DNS app handlers
                 ├── conditional forwarders
                 └── CacheZoneManager : DnsCache  ← resolver record storage
```

`ResolverDnsCache.QueryAsync` merges four sources; only the fourth holds records the resolver
cached, so only the fourth can carry anchor provenance. The obligations below therefore belong to
**`CacheZoneManager`**, and `ResolverDnsCache` satisfies them by delegation.

**Deriving from `DnsCache` does not deliver them.** `CacheZoneManager : DnsCache` overrides
`QueryAsync`, `CacheRecords`, `RemoveExpiredRecords` and `Flush`, calling `base` on none of them,
and stores records in its own `CacheZone` tree. `DnsCache`'s storage, lookup and maintenance never
execute. It derives in order to reach the nested `DnsSpecialCacheRecordData` type and satisfy
`IDnsCache` — it inherits the contract, not the behaviour. Read this as applying to a from-scratch
implementation, because that is effectively what it is.

Use `DnssecCachePolicy` rather than reimplementing these. `DnsCache` calls exactly those methods,
so a cache that calls them matches the reference implementation by construction.

| Obligation | Status in `CacheZoneManager` | Helper |
|---|---|---|
| Preserve per-record provenance | **Already satisfied.** In memory `CacheZone` holds `DnsResourceRecord` instances directly, so the anchor travels with the record. On disk `CacheZone` and `CacheRecordInfo` call `WriteCacheRecordTo` / `ReadCacheRecordFrom`, which carry it in the version 3 record format. | `GetDnssecCacheMetadata()` / `CloneWithDnssecCacheMetadata(...)` |
| Do not set AD under an anchor | **Satisfied incidentally.** AD is derived from `DnssecStatus == Secure`, and an anchored record is `Insecure`. Correct today, but by consequence rather than intent — if that expression is ever relaxed this must be enforced explicitly. | `DnssecCachePolicy.CanSetAuthenticData` |
| Do not serve past anchor expiry | **Not implemented.** `DnsCache` enforces this on its read paths; because `QueryAsync` is overridden, the check never runs. A record admitted *only because validation was suspended* keeps being served after the anchor lapses — precisely the window an NTA exists to close. | `DnssecCachePolicy.HasExpiredNegativeTrustAnchor` |
| Restore provenance on cache hits | Needed for special cache records reconstructed by the server. | `DnssecCachePolicy.RestoreNegativeTrustAnchorAnnotations` |

### A note on `DnsCache`

`DnsCache` remains a correct reference implementation and applies all of the above, but **no
production consumer exercises it**. Do not read "the base class handles it" as coverage for
anything in this table.

## 8. Documented deviations

Where this implementation departs from the specifications, the departure is deliberate and recorded.
The authoritative copy is the XML documentation on `INegativeTrustAnchorProvider`; each implementing
site carries a comment referring back to its identifier. **Pragmatic choices are allowed;
undocumented ones are not.**

| ID | Deviation | Spec text departed from |
|----|-----------|-------------------------|
| **D1** | Root-zone anchors are accepted. Discarding an explicitly configured anchor — which previously happened silently — is more surprising than honouring it. PowerDNS supports and tests a root NTA. The accompanying MUST is not violated: the root has no names above it. | RFC 7646 §2.1 — an NTA "SHOULD be used only in a specific domain or sub-domain" |
| **D2** | EDE 33 is emitted on **causation**, not coverage. A name already insecure for an unrelated reason that merely sits under an anchor produces no EDE here; PowerDNS produces one. This is a strict subset of what the draft permits, so it is conformant, but it is narrower than the reference implementation. | draft §4 — a resolver MAY emit "regardless of whether the presence of the NTA had a material effect" |
| **D3** | The library never emits on its own; the server decides. Satisfying the draft's SHOULD is a deployment responsibility. | draft §4 — an operator applying an NTA "SHOULD return this EDE in affected responses" |
| **D4** | Anchor lifetime is not capped. Names are validated at capture; expiry ceilings are operator policy. See obligation 2. | RFC 7646 §4 — lifetime "SHOULD NOT exceed a week" |
| **D5** | Cache invalidation on anchor add/remove is delegated to the caller. See obligation 4. An earlier revision enforced this in-library with a per-record policy stamp; it was removed because it cost ~800 lines and invalidated the whole cache rather than the affected subtree. | RFC 7646 §4 — "SHOULD remove all cached entries at and below the NTA node" |
| **D6** | EXTRA-TEXT carries structured JSON. The draft registers the names `d` and `t` for this field, so the structured form is offered. The root zone renders as `"."`, since the draft's "no trailing period" rule leaves the root with no usable representation. | RFC 8914 §2 — EXTRA-TEXT is "intended for human consumption (not automated parsing)" |

## 9. Conformance notes

> **Not implemented: positive trust anchor interaction.** RFC 7646 §3 also requires that an NTA at a
> node carrying a configured positive trust anchor (PTA) disables that PTA, and that a PTA further
> down the chain restarts validation. Neither rule is implemented, because nothing in this library
> or in Technitium DNS Server can configure a PTA in the first place — the requirements are vacuous
> rather than violated. An earlier revision carried the machinery for both; it was removed as
> unreachable code threaded through the most delicate part of the resolver. Adding PTA configuration
> later means restoring these two rules alongside it.

Behaviours the library guarantees, which the server should not re-implement or override:

- An NTA **does not affect names above it** in the authentication chain (RFC 7646 §2.1, MUST NOT).
- The AD bit is **not set** on an NTA-affected response (RFC 7646 §1.1).
- Where multiple anchors apply, the **most specific** owner name wins; duplicates merge to the
  **earliest** expiry.
- A DS RRset that is not uniformly `Secure` is **never** treated as an unsigned delegation — an
  unverified DS RRset fails closed rather than silently disabling validation below it.
