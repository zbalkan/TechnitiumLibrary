# TechnitiumLibrary.Net.Tests

Parser robustness tests for malformed DNS resource-record data, prompted by a review
of dnsmasq [CVE-2026-5172](https://www.kb.cert.org/vuls/id/471747) (a declared record
length driving an unchecked read past the record, causing a heap out-of-bounds read).
The equivalent C question does not reproduce here, because the parser is managed code
over bounds-checked streams and `DnsDatagram.ReadFrom` records any parse failure in
`ParsingException` rather than propagating it. Two logic-level relatives do reproduce.

## Test groups

`MalformedRecordParsingTests` — containment guards. A negative or oversized length is
turned into a contained parse exception, never an out-of-bounds read. These pass on the
current code and guard against a future regression toward the C failure mode.

`EmptyRdataKnownBugTests` — reproductions, marked `[TestCategory("KnownBug")]`. They
assert the corrected behaviour and so fail on the current code:

- **Empty RDATA (`RDLENGTH == 0`).** `DnsResourceRecordData` skips `ReadRecordData` when
  the length is zero, so SRV, MX, NS, CNAME and PTR records are accepted with a null
  target. The null then faults `NormalizeName` on the cache-insertion path and
  `UncompressedLength` on the response-sizing path, both with a `NullReferenceException`.
- **Inflated `RDLENGTH` on a structured type.** Name-bearing records are parsed by
  structure and ignore `RDLENGTH`, and the stream position is not reconciled with it
  afterwards, so an oversized `RDLENGTH` silently shifts the parse of every following
  record.

## Running

```
dotnet test --filter "TestCategory!=KnownBug"   # containment guards (expected green)
dotnet test --filter "TestCategory=KnownBug"     # reproductions (expected red until fixed)
```

A fix that rejects zero-length RDATA for name-bearing types and reconciles the stream
position against `RDLENGTH` after `ReadRecordData` turns the `KnownBug` group green; move
those tests out of the category at that point.
