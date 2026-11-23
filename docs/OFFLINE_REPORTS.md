# Offline Nuclei triage reports

This derivative preserves reconFTW's MIT license and upstream scan modes.
The additions here do **not** install scanners, contact targets, expand discovery,
or change the request rate. No production scan is needed to use or test them.

## Reduced-data export

Use Python 3.7+ (standard library only) to process **existing** Nuclei JSONL files,
including reconFTW's `nuclei_output/*_json.txt` files:

```sh
mkdir -p output
python3 lib/nuclei_report.py \
  --input Recon/example.com/nuclei_output/high_json.txt \
  --input Recon/example.com/nuclei_output/medium_json.txt \
  --output output/triage.json
```

Repeat `--input` for additional files. Use `--format csv` with a `.csv` destination
for spreadsheet import. There is no implicit directory scan or network request.
Avoid supplying both a combined result and its per-severity copies unless you
intend to count the same input observations again.

### What is retained

| Field | Meaning |
|---|---|
| `template_id` | Scanner template identifier; not a verified vulnerability |
| `severity` | Severity reported by the template, not reassessed here |
| `type` | Scanner protocol/type |
| `origin` | Canonical HTTP(S) scheme, hostname/IP and non-default port |
| `occurrences` | Number of input records in this group |
| `verification` | Always `unverified` |

Records are grouped by template ID, severity, type and origin in one input pass.
Different paths and matchers on the same origin intentionally collapse into the
same group. **Group counts are not vulnerability counts or distinct endpoints.**
Sorting is deterministic, with higher reported severity first.

Only these fields are emitted. Request/response bodies, extracted values,
matcher names, template paths, titles, descriptions, unknown metadata, URL
userinfo, paths, query strings and fragments are not copied into the export.
HTTP(S) origins are normalized for case, IDNA, IPv6 and default ports.
Records without an HTTP(S) `matched-at` or `host` are omitted and counted in the
JSON summary and CLI status. This is not an exporter for non-web findings.

**Review before sharing.** Hostnames, IP addresses and template IDs remain;
those identifiers can themselves be sensitive. This is data minimization, not a
guarantee of anonymization. The original JSONL, normal reconFTW exports, logs,
asset stores and AI reports are **unchanged and may still contain sensitive
content**. Do not share the entire scan directory on the strength of this export.

### Failure and storage behavior

- JSONL is read line by line; memory grows with distinct groups, not raw bodies.
- A line is limited to 4 MiB, including its newline. Override only when needed
  with `--max-line-bytes <positive integer>`.
- Malformed JSON/UTF-8, invalid identifiers, unsupported severity/type, malformed
  HTTP URLs or I/O errors fail the export. No partial report is published.
- Validation messages identify the input ordinal and line, not the raw data.
- Empty files are valid; blank lines are ignored.
- Output is staged beside its destination, flushed, then atomically replaced.
  A previous report survives parse/write failures before replacement.
- Output permissions are `0600`. The parent directory must already exist.
- Output cannot be a symlink, non-regular file (including directories, devices,
  FIFOs and sockets), input file or hardlink to an input.
- Exit code `0` means export succeeded; `2` means invalid input or I/O failure.

This helper has no dependencies on Nuclei or reconFTW's installed tool suite.
It does not verify a finding, test scope ownership or establish authorization.

## Scope-file write safety

The existing `check_inscope` helper now uses a unique temporary file in the input
file's directory rather than a predictable `<input>_tmp` path. It publishes with
rename only after the filter succeeds; errors clean up the staged file and leave
the original intact. Input symlinks/directories are rejected, and successful
output has private `0600` permissions. The directory must be writable.

This hardens file handling only. It does **not** make every scan mode fail-closed
or make the existing `passive` mode strictly passive. Existing callers still need
to handle the helper's nonzero result.

## Tests

```sh
python3 tests/unit/test_nuclei_report.py
bats tests/unit/test_check_inscope.bats tests/unit/test_nuclei_report.bats
pre-commit run --files modules/core.sh lib/nuclei_report.py \
  tests/unit/test_check_inscope.bats tests/unit/test_nuclei_report.bats \
  tests/unit/test_nuclei_report.py
```

Use bats-core 1.5+ so tests have isolated `BATS_TEST_TMPDIR` directories. The
Python suite is also invoked by the Bats unit suite in CI and pre-commit. Tests
use synthetic `example.com` records and stubbed commands, not live services.
