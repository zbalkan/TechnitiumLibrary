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

## Expanded campaign plan

Pull requests use **three minutes per AFL++ target**. Scheduled campaigns
use 30 minutes nightly (Monday–Saturday, 02:17 UTC) and 120 minutes
weekly (Sunday, 02:23 UTC). Schedules become operational on the default
branch when this PR merges. Manual dispatch accepts durations from
1 to 240 minutes. The five specialized harnesses run as independent
matrix jobs; these are parallel campaigns, not simultaneous workers
competing for CPUs within the same runner.

`SpecializedTargets.cs` exercises DNS-name compression directly, and
RDATA, EDNS, and DNSSEC decoding through bounded record wrappers.
The serialization target checks parse/serialize/parse invariants.
Malformed input stored as `DnsDatagram.ParsingException` is not treated
as a process crash. `generate_target_seeds.py` supplies focused seeds,
while `generate_structured_seeds.py` adds deterministic grammar-aware
mutations of counts, lengths, labels and pointers.

Both the main and specialized workflows read SHA-256-verified, bounded
corpus artifacts from prior successful runs on the same repository,
branch and workflow. Inputs are exploratory, never automatically
promoted into the regression corpus. Corpus snapshots preserve exact
input bytes and report that byte deduplication is **not** coverage
minimization. A missing or unavailable prior artifact does not prevent
a fresh-seed campaign.

`campaign_metrics.py` extracts execution throughput, AFL++ bitmap
coverage, stability, queue size, crash/hang counts, and measured edge
growth from the AFL++ statistics. No bitmap figure is represented as
source-code or branch coverage. These measurements allow comparison
of campaigns and identification of stagnation.

The live-server fixture additionally tests fragmented DNS-over-TCP
frames, sequential and pipelined requests, incomplete frames, zero
lengths and availability after each state transition.

`differential.py` compares acceptance and common DNS-header semantics
against dnspython using the clean parser's `--inspect` mode. Differential
discrepancies are review leads, not automatically confirmed bugs.
Diagnostics and input hashes are archived for triage.

For manually dispatched campaigns, `benchmark_modes.py` measures clean
parser startup overhead versus repeated calls inside one .NET process.
The benchmark is an **estimate of potential persistent execution
benefit**, not proof of AFL++ persistent-mode improvement. Adopting
persistent fuzzing remains conditional on an instrumented A/B comparison
and equivalence of the crash and semantic oracles.

## Reproducible AFL++ bug evidence

When clean-harness replay reproduces a crash or hang, `triage.py`
creates one **standalone reproducer folder per provisional failure signature**
inside the existing AFL++ evidence artifact, under
`triage/reproducers/<signature>/`. Each folder contains the exact,
unmodified `input.bin`, `metadata.json` (SHA-256, target, source
revision, timeout, exit code, normalized signature, candidate hashes),
`replay-output.txt`, and a `README.md` with the build and replay
instructions. A separate `environment.txt` in `triage/` records
the .NET runtime, platform, checked-out commit, and hashes of clean
harness assemblies. These packages remain available for 30 days.

Rebuild the clean harness from the recorded source revision, then run
the verifier against a reproducer folder. The verifier checks that the
input bytes match the recorded SHA-256 and that replay reproduces the
expected classification, exit code, and stack signature. Its exit code
is 0 only when the recorded failure reproduces; 1 means the observed
behavior differs; 2 means an invalid bundle or execution error.

One representative per signature is chosen by shortest input length,
breaking ties by SHA-256, **without changing its bytes**. This is
representative selection, not test-case minimization. All discovered
candidate inputs and individual replay results remain in the evidence
artifact. Provisional groups may contain multiple underlying defects.
`confirmed_defects: 0` still means no automatic vulnerability
classification: a reproducible oracle failure needs engineering review.

The fuzzing workflows intentionally **fail when AFL++ finds crashes**.
No production parser or oracle behavior is modified to hide findings.
