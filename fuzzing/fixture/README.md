# Fuzzing fixture

Scripts that configure a Technitium DNS Server instance as a fuzzing target
through its HTTP API, check the result, and save a backup that later runs
restore from. They use the Python standard library only (Python 3.11+).

This fixture lives in TechnitiumLibrary. The GitHub Actions workflow builds
this branch of the library alongside a pinned upstream DnsServer checkout,
using the sibling-directory layout expected by the server project references.

Scope for this phase: the server and TechnitiumLibrary over DNS-over-UDP and
DNS-over-TCP. DNS apps, the HTTP API as a target, DoT, DoH, DoQ, plain
DNS-over-HTTP and the PROXY protocol are out of scope and disabled by the
base profile.

## Layout

| Path | Purpose |
|---|---|
| `profiles/base.toml` | Authoritative zones with restricted recursion to exercise blocking, rate limits removed, full stack traces in the logs |
| `zones/*.zone` | RFC 1035 zone files imported into the four fixture zones |
| `tdns.py` | API client, profile loading, serialisation and comparison |
| `wait_ready.py` | Waits until the API accepts a login |
| `provision.py` | Applies a profile; `--backup` saves a settings backup zip |
| `verify.py` | Diffs settings and zone options against the profile, then queries each zone's SOA over UDP and TCP |
| `restore.py` | Restore utility; not used by fuzzing CI until backup consistency is resolved |
| `fuzz_dns.py` | Seeded malformed DNS packet campaign, UDP/TCP liveness oracle and JSON evidence |
| `log_oracle.py` | Detect unexpected exception records added to server logs after provisioning; write JSON evidence and fail the job |
| `log_exception_allowlist.json` | Explicit, reasoned exceptions permitted by the server-log oracle (currently empty) |
| `tests/` | Unit and end-to-end tests against local fakes of the API and DNS listeners |

## Environment

| Variable | Used by | Meaning |
|---|---|---|
| `FIXTURE_API_URL` | `wait_ready.py`, `provision.py`, `verify.py`, `restore.py` | API base URL, default `http://127.0.0.1:5380` |
| `FIXTURE_API_USER` | `wait_ready.py`, `provision.py`, `verify.py`, `restore.py` | Default `admin` |
| `FIXTURE_API_PASSWORD_FILE` or `FIXTURE_API_PASSWORD` | `wait_ready.py`, `provision.py`, `verify.py`, `restore.py` | Admin password |
| `FIXTURE_TSIG_SECRET` | profiles | Base64 TSIG secret for `fuzz-key` |
| `FIXTURE_FUZZER_NET` | all profiles | Fuzzer subnet allowed to exercise the blocking path and, in the variant, UPDATE and transfer requests |
| `FIXTURE_DNS_HOST`, `FIXTURE_DNS_PORT` | `verify.py` | DNS listener for the smoke queries, default `127.0.0.1:53` |

## Profiles

Values under `[settings]` use the shape that `/api/settings/get` returns, so
`verify.py` can compare them directly; `provision.py` converts them to the
form `/api/settings/set` expects. Settings that the server accepts but does
not report under the same key go in `[settings_write_only]`. A variant names
its parent with `extends` and changes inherited zones through
`[zone_options."<zone>"]`. Secrets are written as `${ENV:NAME}`.

Authoritative SOA probes use RD=0. Blocked-domain probes use RD=1 over
both UDP and TCP: Technitium checks blocked zones in its recursive path.
The base profile permits recursion only from loopback and the fuzzer subnet,
and disables the locally served special-use `.test` handler, which could
otherwise return NXDOMAIN without exercising blocking. CI creates an
`--internal` Docker network to prevent outbound traffic. Apply equivalent
network egress isolation when running the fixture manually.

## Running

```sh
python3 -m unittest discover -s tests -t . -v
python3 wait_ready.py
python3 provision.py --profile profiles/base.toml --backup out/fixture-backup.zip
python3 verify.py --profile profiles/base.toml
python3 fuzz_dns.py --output out/fuzz-evidence.json --seed 20261106 --count 80
```

In CI the web service listens on `127.0.0.1` inside the server container, so
only the API-facing setup scripts run in a sidecar sharing its network
namespace. `fuzz_dns.py` runs in a separate container on `fuzznet` without
API credentials and reaches the server only through its DNS listener
(see `.github/workflows/fuzz-fixture.yml`). The workflow runs on pushes to
`fuzz/**` branches that change the fixture, on relevant pull requests, and can
be dispatched manually using the base profile. Signed UPDATE and AXFR/IXFR
variants are deferred until the campaign actually exercises those operations. It validates the fixture and sends 80 deterministic malformed DNS inputs over both UDP and TCP from a container on the internal Docker network. Response timeouts and disconnects are counted, not automatically treated as server defects. A valid authoritative SOA probe checks service availability over both transports every ten inputs. JSON evidence includes the seed, outcome counts and, for a health failure, the triggering packet in hexadecimal. This is a bounded smoke campaign, not coverage-guided fuzzing or DNS protocol-conformance testing. The workflow does not restore from the backup while consistency is unresolved. The upstream checkout is pinned for reproducibility.

## Server exception oracle (Phase 1.1)

The fixture captures the server's `/etc/dns/logs` folder after provisioning and again after the DNS campaigns. The scanner compares each file against the pre-campaign byte prefix and examines only appended log entries. Newly created log files are also inspected. A missing log directory, missing baseline, changed prefix, or unexpected exception fails the scanner. Exception records include timestamp, type, message and up to five top stack frames in `log-oracle-evidence.json`.

The allowlist is initially empty. If a documented expected rejection genuinely produces an exception log, add a rule with the fully qualified exception type, an anchored message regular expression, and a reason. Do not broadly allow exceptions solely because the server remains available.

This is a log-based regression oracle, not packet attribution or a DNS response-semantics oracle. Phase 1.2 will attribute exceptions to individual inputs; Phase 1.5 will add a network-path negative control. The existing unit tests exercise a representative multiline exception record but do not replace the live negative control.
