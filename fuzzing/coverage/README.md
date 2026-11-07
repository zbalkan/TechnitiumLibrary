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

This oracle tests process-level containment, not whether all malformed DNS
records are rejected correctly. Semantic validation, parser-consistency
invariants, and live-server availability remain separate test objectives.

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
