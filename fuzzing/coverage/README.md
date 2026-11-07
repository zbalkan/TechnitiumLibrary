# Coverage-guided DNS parser fuzzing

This project targets `TechnitiumLibrary.Net.Dns.DnsDatagram.ReadFrom(Stream)`.
It does **not** use the DNS server or its HTTP API. SharpFuzz 2.3.0
instruments the managed `TechnitiumLibrary.Net.dll` to report coverage
to AFL++. The AFL++ corpus contains DNS questions, resource records, EDNS
and malformed compression pointers. The workload is separate from the
bounded network smoke test in `../fixture/`.

The crash oracle follows the production parser contract: malformed record and
EDNS input is reported by `DnsDatagram.ReadFrom` through the returned
datagram's `ParsingException` property. Such a stored exception is a
rejected message, **not** a crash, regardless of the exception type. Truncated
DNS headers may throw `EndOfStreamException` before the parser's internal
catch boundary; the oracle accepts that outcome. Any other exception escaping
`ReadFrom` is reported as an AFL++ crash. No production parser code is
modified.

Run `dotnet DnsParserFuzz.dll --test-oracle` against an uninstrumented build
to verify valid parsing, stored malformed-RSA-key rejection, truncated-header
handling, and that an injected escaping exception is not swallowed.

The bounded semantic oracle checks identifier, response bit, and section-count
invariants for successfully parsed messages. The reviewed seed corpus has
explicit valid/rejected expectations and valid seeds must survive a semantic
parse–serialize–parse round-trip. These checks intentionally do not equate
all accepted mutations with valid DNS packets; full protocol conformance,
resource budgets, and live-server resilience are separate later phases.
Run `dotnet DnsParserFuzz.dll --verify-seeds /tmp/tdns-parser-seeds`
against the clean, uninstrumented harness to verify the curated corpus.

## Run on Ubuntu 24.04 with .NET 10

Install AFL++ and SharpFuzz's command-line instrumenter, then build and
publish the harness. Run `generate_seeds.py` to create a local binary
corpus. Instrument the *published* `TechnitiumLibrary.Net.dll` rather
than the original build output; this preserves the source tree.

```sh
sudo apt-get update && sudo apt-get install -y afl++
dotnet tool install --global SharpFuzz.CommandLine --version 2.3.0
dotnet publish fuzzing/coverage/DnsParserFuzz/DnsParserFuzz.csproj -c Release -o /tmp/tdns-parser-fuzz
python3 fuzzing/coverage/generate_seeds.py --output /tmp/tdns-parser-seeds
$HOME/.dotnet/tools/sharpfuzz /tmp/tdns-parser-fuzz/TechnitiumLibrary.Net.dll
AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 afl-fuzz -i /tmp/tdns-parser-seeds -o /tmp/tdns-parser-findings -m none -t 5000+ -- dotnet /tmp/tdns-parser-fuzz/DnsParserFuzz.dll
```

For deterministic replay of a corpus file or crash, use an **unmodified**
copy of the harness and library: `dotnet DnsParserFuzz.dll --replay INPUT`.
If AFL++ reports a crash, keep the input and stack trace for triage.
Do not treat a stored `ParsingException` as a process crash.

This is a bounded, opt-in CI smoke run using AFL++ feedback. Coverage
instrumentation is real, but a short run is not evidence of comprehensive
branch coverage. Corpus growth and deeper campaigns belong in later work.

## Initial triage

The initial campaigns reported crash candidates after the harness
incorrectly rethrew errors stored in `ParsingException`. These included
malformed RSA DNSKEY encodings and unsupported record formats. Production
`ReadFrom` already catches those errors. The RSA length-validation change
was therefore reverted from the fuzzing branch; the revised oracle tests
the actual parser boundary rather than a list of acceptable exception types.
The isolated RSA fix branch is not part of this fuzzing workflow.

## Phase 2: protocol-aware corpus and promotion

`generate_seeds.py` includes DNSSEC (DS, DNSKEY, RRSIG, NSEC, NSEC3),
EDNS ECS and unknown options, multi-section messages, name boundaries,
and malformed count/length cases. These additional inputs are **mutation
seeds**, not an assertion that their cryptographic content or packet
structure is accepted as valid. Only the 16 explicitly reviewed cases in
`--verify-seeds` carry strict acceptance or rejection expectations.

The `regressions/` directory is for manually reviewed replay inputs,
named by their SHA-256 digest. Do not promote every AFL queue entry:
interesting coverage alone does not establish a defect. Promote only a
confirmed, minimized reproducer with a written classification. CI always
replays these persisted inputs using the production-equivalent parser
oracle.

Run `corpus.py promote --source INPUT --destination
fuzzing/coverage/regressions` after triage. It rejects empty inputs,
oversized DNS messages, and hash collisions. Files are binary and
deduplicated by content. Add the resulting file to the PR only after review.

## Corpus compaction and minimization limitations

The SharpFuzz out-of-process harness produces meaningful AFL++ feedback
during fuzzing, but the separate AFL++ coverage-minimization tools have
not worked with it. With `AFL_NO_FORKSRV=1`, `afl-cmin` was
prohibitively slow. A bounded `afl-showmap` experiment measured zero
usable edges after 75 seconds; a forkserver-enabled experiment also
measured zero edges from 88 inputs. Neither result demonstrates that
the DNS inputs have no coverage.

The optional CI corpus snapshot uses `corpus.py snapshot` to preserve
**every byte-distinct input** from generated seeds and the AFL++ queue,
naming them by SHA-256 and recording provenance in `manifest.json`.
This removes exact duplicates without discarding any unique input.
It deliberately sets `coverage_minimized: false`: content
deduplication is not coverage minimization. This artifact is not
automatically promoted into the reviewed regression corpus.

Proper edge-guided minimization remains deferred until an
instrumentation-compatible coverage measurement path is established.

## Phase 3: finding evidence, classification, and replay

`triage.py` replays AFL++ crash and hang candidates against the saved
**uninstrumented** parser harness. Each replay records its SHA-256 input
hash, byte count, original AFL filename, process exit status, bounded
diagnostic output, provisional signature, and classification in
`triage/report.json`. Identical payloads share one evidence binary.
Signature clusters are investigative hints, not proof of a shared root
cause. A replay that exits successfully is **not reproducible** as a
process failure, even if the fuzzer originally labeled it a crash.
A stored `DnsDatagram.ParsingException` remains normal rejection.

Classification distinguishes non-reproducible candidates, escaping
exceptions, timeouts, abnormal process exits, runner errors, and
oversized inputs. No candidate is automatically confirmed or promoted
into `regressions/`. Triage imposes a per-candidate timeout, a
100-candidate maximum, and a 32 KiB diagnostic-output cap.
The structured report and replay evidence are packaged with the
existing AFL++ CI artifact. An empty candidate set still yields a
machine-readable report with zero confirmed defects.

For confirmed fixes, first minimize the reproducer and document the
root cause, expected behavior, and GitHub issue/PR in the review.
Promote only the reviewed binary with `corpus.py promote`. The PR's
regression-replay workflow exercises all stored inputs using the
uninstrumented parser; a process crash or timeout will fail that step.
