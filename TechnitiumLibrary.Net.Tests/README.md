# TechnitiumLibrary.Net.Tests

Parser robustness tests for malformed DNS resource-record data, prompted by a review
of dnsmasq [CVE-2026-5172](https://www.kb.cert.org/vuls/id/471747) (a declared record
length driving an unchecked read past the record, causing a heap out-of-bounds read).
The equivalent C question does not reproduce here, because the parser is managed code
over bounds-checked streams and `DnsDatagram.ReadFrom` catches failures raised while
parsing the question and resource records, recording them in `ParsingException` rather
than propagating them; the fixed-size header is read before that handler, so a truncated
header still throws. Two logic-level relatives did surface, and both are fixed in
`DnsResourceRecordData` by reconciling the bytes consumed against `RDLENGTH`.

## Test groups

`MalformedRecordParsingTests` — containment guards. `RDLENGTH` is a 16-bit unsigned
field, so it is never itself negative; an undersized value drives a negative
record-specific read length (for example SSHFP computing `RDLENGTH - 2`), while an
oversized value would read past the datagram. Both become a contained parse exception
rather than an out-of-bounds read, which guards against a regression toward the C
failure mode.

`MalformedRdataRejectionTests` — the two fixed defects, now asserted as rejections:

- **Empty RDATA (`RDLENGTH == 0`) on a name-bearing type.** SRV, MX, NS, CNAME and PTR
  used to be accepted with a null target, which then faulted `NormalizeName` (cache
  path) and `UncompressedLength` (sizing path) with a `NullReferenceException`. Such a
  record is now rejected into `ParsingException`.
- **`RDLENGTH` that disagrees with a structured type's real length.** The length is now
  enforced, so an inflated `RDLENGTH` can no longer shift the parse of the records that
  follow.

## The fix

`DnsResourceRecordData(Stream)` now parses the RDATA unconditionally and then requires
the parse to have consumed exactly `RDLENGTH` bytes, throwing otherwise. A zero-length
name-bearing record over-reads its fixed structure and is rejected; a length that
disagrees with the structure is rejected before it can desync the following records.

## Running

```
dotnet test
```
