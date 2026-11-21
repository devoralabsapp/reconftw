#!/usr/bin/env python3
"""Export a reduced-data, offline triage report from existing Nuclei JSONL."""

import argparse
import csv
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from urllib.parse import urlsplit


SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
TYPES = frozenset(("http", "headless", "dns", "network", "tcp", "udp", "ssl", "file", "websocket",
                   "whois", "code", "javascript", "offline-http", "unknown"))
FIELDS = ("template_id", "severity", "type", "origin", "occurrences", "verification")
DEFAULT_MAX_LINE_BYTES = 4 * 1024 * 1024


class ReportError(ValueError):
    """An error whose message never includes source data."""


def http_origin(value):
    """Keep only a canonical HTTP(S) origin, never URL credentials or paths."""
    if not isinstance(value, str):
        raise ReportError("invalid URL field")
    if not value.lower().startswith(("http://", "https://")):
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in value) or "\\" in value:
        raise ReportError("invalid HTTP URL")
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
        if not host or "%" in host or port == 0:
            raise ValueError
        host = host[:-1] if host.endswith(".") else host
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            host = host.encode("idna").decode("ascii").lower()
            if len(host) > 253 or not all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in host.split(".")
            ):
                raise ValueError
        else:
            host = "[{}]".format(address.compressed) if address.version == 6 else str(address)
        scheme = parsed.scheme.lower()
        if port is not None and port != {"http": 80, "https": 443}[scheme]:
            host += ":{}".format(port)
        return "{}://{}".format(scheme, host)
    except (ValueError, UnicodeError):
        raise ReportError("invalid HTTP URL") from None


def observation_key(record):
    if not isinstance(record, dict):
        raise ReportError("expected a JSON object")
    template_id = record.get("template-id")
    if not isinstance(template_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", template_id):
        raise ReportError("invalid or missing template-id")
    info = record.get("info", {})
    if not isinstance(info, dict):
        raise ReportError("invalid info object")
    severity = info.get("severity", "unknown")
    scan_type = record.get("type", "unknown")
    if not isinstance(severity, str) or severity not in SEVERITIES:
        raise ReportError("invalid severity")
    if not isinstance(scan_type, str) or scan_type not in TYPES:
        raise ReportError("invalid type")
    for field in ("matched-at", "host"):
        value = record.get(field)
        if value is not None:
            origin = http_origin(value)
            if origin is not None:
                return template_id, severity, scan_type, origin
    return None


def aggregate(inputs, max_line_bytes=DEFAULT_MAX_LINE_BYTES):
    counts = {}
    records = 0
    omitted = 0
    for file_number, path in enumerate(inputs, 1):
        with Path(path).open("rb") as stream:
            line_number = 0
            while True:
                line = stream.readline(max_line_bytes + 1)
                if not line:
                    break
                line_number += 1
                location = "input {}, line {}".format(file_number, line_number)
                if len(line) > max_line_bytes:
                    raise ReportError(location + ": line exceeds size limit")
                if not line.strip():
                    continue
                try:
                    record = json.loads(line.decode("utf-8"))
                except (ValueError, UnicodeError, RecursionError):
                    raise ReportError(location + ": invalid JSON/UTF-8") from None
                try:
                    key = observation_key(record)
                except ReportError as error:
                    raise ReportError(location + ": " + str(error)) from None
                records += 1
                if key is None:
                    omitted += 1
                else:
                    counts[key] = counts.get(key, 0) + 1
    findings = []
    for key in sorted(counts, key=lambda item: (SEVERITIES.index(item[1]), item[0], item[3], item[2])):
        findings.append(dict(zip(FIELDS, (*key, counts[key], "unverified"))))
    return {
        "schema_version": 1,
        "notice": "Unverified scanner observations, grouped by template, severity, type and HTTP(S) origin; not confirmed vulnerabilities. Review retained identifiers before sharing.",
        "summary": {
            "input_records": records,
            "included_records": records - omitted,
            "omitted_non_http_records": omitted,
            "groups": len(findings),
        },
        "findings": findings,
    }


def validate_paths(inputs, output):
    if output.is_symlink() or output.is_dir():
        raise ReportError("output must be a regular file, not a symlink or directory")
    for source in inputs:
        if source.resolve() == output.resolve() or (output.exists() and os.path.samefile(source, output)):
            raise ReportError("output must not replace an input file")


def publish(report, output, output_format):
    staged = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="", prefix=".nuclei-report-", dir=output.parent, delete=False) as stream:
            staged = stream.name
            if output_format == "json":
                json.dump(report, stream, ensure_ascii=True, indent=2)
                stream.write("\n")
            else:
                writer = csv.DictWriter(stream, fieldnames=FIELDS)
                writer.writeheader()
                writer.writerows(report["findings"])
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(staged, output)
    finally:
        if staged is not None and os.path.exists(staged):
            os.unlink(staged)


def positive_int(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("expected a positive integer") from None
    if number < 1:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, action="append", required=True, help="Existing JSONL file; repeat to combine files (including reconFTW *_json.txt).")
    parser.add_argument("--output", type=Path, required=True, help="Report destination; parent directory must exist.")
    parser.add_argument("--format", choices=("json", "csv"), default="json")
    parser.add_argument("--max-line-bytes", type=positive_int, default=DEFAULT_MAX_LINE_BYTES, help="Maximum bytes per input line, including newline (default: 4 MiB).")
    args = parser.parse_args(argv)
    try:
        validate_paths(args.input, args.output)
        report = aggregate(args.input, args.max_line_bytes)
        publish(report, args.output, args.format)
    except ReportError as error:
        print("Report not written: " + str(error), file=sys.stderr)
        return 2
    except OSError:
        print("Report not written: cannot read inputs or publish output; check paths and permissions.", file=sys.stderr)
        return 2
    summary = report["summary"]
    print("Wrote {groups} unverified groups from {included_records} HTTP(S) records; omitted {omitted_non_http_records} non-HTTP records.".format(**summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
