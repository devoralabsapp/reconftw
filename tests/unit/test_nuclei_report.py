#!/usr/bin/env python3
"""Offline-only regression tests using synthetic scanner output."""

import contextlib
import csv
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "nuclei_report", Path(__file__).resolve().parents[2] / "lib/nuclei_report.py"
)
reporter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reporter)


def observation(**changes):
    record = {
        "template-id": "example-check",
        "type": "http",
        "info": {"severity": "low", "name": "Untrusted name"},
        "matched-at": "https://example.com/a?token=SECRET",
    }
    record.update(changes)
    return record


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "scanner.jsonl"
        self.output = self.root / "report.json"
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()

    def write_records(self, *records, path=None):
        target = path or self.source
        target.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
        return target

    def cli(self, *extra):
        with contextlib.redirect_stdout(self.stdout), contextlib.redirect_stderr(self.stderr):
            return reporter.main(["--input", str(self.source), "--output", str(self.output), *extra])

    def test_redaction_uses_explicit_field_allowlist(self):
        self.write_records(observation(**{
            "matched-at": "https://user:SECRET@EXAMPLE.com:443/path/SECRET?token=SECRET#SECRET",
            "request": "Authorization: Bearer SECRET",
            "response": "Set-Cookie: SECRET",
            "extracted-results": ["SECRET"],
            "matcher-name": "SECRET",
            "template-path": "/home/SECRET/custom.yaml",
            "info": {"severity": "low", "name": "SECRET", "description": "SECRET"},
            "unrecognized-field": {"secret": "SECRET"},
        }))
        before = self.source.read_bytes()
        self.assertEqual(self.cli(), 0)
        text = self.output.read_text()
        self.assertNotIn("SECRET", text + self.stdout.getvalue() + self.stderr.getvalue())
        finding = json.loads(text)["findings"][0]
        self.assertEqual(set(finding), set(reporter.FIELDS))
        self.assertEqual(finding["origin"], "https://example.com")
        self.assertEqual(finding["verification"], "unverified")
        self.assertEqual(self.source.read_bytes(), before)

    def test_grouping_across_inputs_counts_observations_not_vulnerabilities(self):
        self.write_records(observation(), observation(**{"matched-at": "https://example.com/other"}))
        other = self.write_records(observation(), path=self.root / "second.jsonl")
        result = reporter.aggregate([self.source, other])
        self.assertEqual(result["summary"]["groups"], 1)
        self.assertEqual(result["summary"]["included_records"], 3)
        self.assertEqual(result["findings"][0]["occurrences"], 3)

    def test_canonical_origins(self):
        cases = {
            "https://EXAMPLE.com.:443/a": "https://example.com",
            "http://example.com:80/a": "http://example.com",
            "https://example.com:8443/a": "https://example.com:8443",
            "https://[2001:0db8:0:0::1]:443/a": "https://[2001:db8::1]",
            "http://192.0.2.1:8000/a": "http://192.0.2.1:8000",
            "https://bücher.example/a": "https://xn--bcher-kva.example",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(reporter.http_origin(value), expected)

    def test_malformed_http_urls_are_rejected_without_echo(self):
        for value in ("https://", "https://bad%20host/SECRET", "https://bad host/SECRET",
                      "https://a.test:65536/SECRET", "https://a.test:0/SECRET",
                      "https://a.test\n/SECRET", "https://a.test\\SECRET", "https://[not-ip]/SECRET",
                      "https://-bad.test/SECRET", "https://a..test/SECRET"):
            with self.subTest(value=value):
                with self.assertRaises(reporter.ReportError) as error:
                    reporter.http_origin(value)
                self.assertNotIn("SECRET", str(error.exception))

    def test_no_network_access(self):
        self.write_records(observation())
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            self.assertEqual(self.cli(), 0)

    def test_non_http_records_are_omitted_and_counted(self):
        self.write_records(observation(), observation(**{"matched-at": "example.com", "type": "dns"}))
        result = reporter.aggregate([self.source])
        self.assertEqual(result["summary"], {
            "input_records": 2, "included_records": 1,
            "omitted_non_http_records": 1, "groups": 1,
        })

    def test_host_is_used_when_matched_at_is_absent(self):
        self.write_records(observation(**{"matched-at": None, "host": "https://example.net/a"}))
        self.assertEqual(reporter.aggregate([self.source])["findings"][0]["origin"], "https://example.net")

    def test_default_ports_merge_but_distinct_origins_and_templates_do_not(self):
        self.write_records(
            observation(), observation(**{"matched-at": "https://example.com:443/b"}),
            observation(**{"matched-at": "https://example.com:8443"}),
            observation(**{"matched-at": "http://example.com"}),
            observation(**{"template-id": "another-check"}),
        )
        result = reporter.aggregate([self.source])
        self.assertEqual(result["summary"]["groups"], 4)
        self.assertEqual(sum(item["occurrences"] for item in result["findings"]), 5)

    def test_severity_sort_and_determinism(self):
        self.write_records(observation(), observation(info={"severity": "critical"}))
        first = reporter.aggregate([self.source])
        self.write_records(observation(info={"severity": "critical"}), observation())
        self.assertEqual(reporter.aggregate([self.source]), first)
        self.assertEqual(first["findings"][0]["severity"], "critical")

    def test_blank_lines_and_empty_files(self):
        self.source.write_text("\n \n")
        self.assertEqual(self.cli(), 0)
        self.assertEqual(json.loads(self.output.read_text())["summary"]["input_records"], 0)

    def test_missing_optional_fields_become_unknown(self):
        self.write_records({"template-id": "example-check", "host": "https://example.com"})
        item = reporter.aggregate([self.source])["findings"][0]
        self.assertEqual(item["severity"], "unknown")
        self.assertEqual(item["type"], "unknown")

    def test_csv_contains_only_allowlisted_columns(self):
        self.write_records(observation(**{"response": "SECRET"}))
        self.assertEqual(self.cli("--format", "csv"), 0)
        with self.output.open(newline="") as stream:
            reader = csv.DictReader(stream)
            self.assertEqual(reader.fieldnames, list(reporter.FIELDS))
            self.assertEqual(next(reader)["verification"], "unverified")
        self.assertNotIn("SECRET", self.output.read_text())

    def test_invalid_fields_and_csv_formula_injection_are_rejected(self):
        invalid = [None, [], "SECRET", observation(**{"template-id": "=SECRET()"}),
                   observation(**{"template-id": "bad\nSECRET"}), observation(info=[]),
                   observation(info={"severity": ["SECRET"]}), observation(type="SECRET"),
                   observation(**{"matched-at": ["SECRET"]}), observation(**{"template-id": ""})]
        for record in invalid:
            with self.subTest(record=record):
                self.write_records(record)
                self.assertEqual(self.cli(), 2)
                self.assertFalse(self.output.exists())
        self.assertNotIn("SECRET", self.stderr.getvalue())

    def test_parse_errors_preserve_existing_output(self):
        self.source.write_text(json.dumps(observation()) + "\nSECRET malformed\n")
        self.output.write_text("previous report")
        self.assertEqual(self.cli(), 2)
        self.assertEqual(self.output.read_text(), "previous report")
        self.assertIn("input 1, line 2", self.stderr.getvalue())
        self.assertNotIn("SECRET", self.stderr.getvalue())

    def test_second_input_failure_is_atomic(self):
        self.write_records(observation())
        other = self.root / "second.jsonl"
        other.write_text("SECRET malformed")
        self.output.write_text("previous report")
        self.assertEqual(self.cli("--input", str(other)), 2)
        self.assertEqual(self.output.read_text(), "previous report")
        self.assertIn("input 2, line 1", self.stderr.getvalue())

    def test_invalid_utf8_is_not_echoed(self):
        self.source.write_bytes(b'\xffSECRET')
        self.assertEqual(self.cli(), 2)
        self.assertNotIn("SECRET", self.stderr.getvalue())

    def test_oversized_lines_fail_before_parsing(self):
        self.source.write_text("SECRET" * 1000)
        self.assertEqual(self.cli("--max-line-bytes", "100"), 2)
        self.assertIn("size limit", self.stderr.getvalue())
        self.assertFalse(self.output.exists())
        self.assertNotIn("SECRET", self.stderr.getvalue())

    def test_private_permissions_also_replace_existing_public_file(self):
        self.write_records(observation())
        self.output.write_text("previous")
        self.output.chmod(0o644)
        self.assertEqual(self.cli(), 0)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)

    def test_output_cannot_replace_input_or_hardlink(self):
        self.write_records(observation())
        before = self.source.read_bytes()
        self.output = self.source
        self.assertEqual(self.cli(), 2)
        self.output = self.root / "hardlink"
        os.link(self.source, self.output)
        self.assertEqual(self.cli(), 2)
        self.assertEqual(self.source.read_bytes(), before)

    def test_symlink_output_is_rejected(self):
        self.write_records(observation())
        target = self.root / "unrelated"
        target.write_text("keep")
        self.output.symlink_to(target)
        self.assertEqual(self.cli(), 2)
        self.assertEqual(target.read_text(), "keep")
        self.assertTrue(self.output.is_symlink())

    def test_publish_failure_cleans_staging_and_preserves_output(self):
        self.write_records(observation())
        self.output.write_text("keep")
        with patch.object(reporter.os, "replace", side_effect=OSError("SECRET")):
            self.assertEqual(self.cli(), 2)
        self.assertEqual(self.output.read_text(), "keep")
        self.assertEqual(list(self.root.glob(".nuclei-report-*")), [])
        self.assertNotIn("SECRET", self.stderr.getvalue())

    def test_missing_files_or_parent_produce_no_report(self):
        self.assertEqual(self.cli(), 2)
        self.write_records(observation())
        self.output = self.root / "missing-parent" / "report.json"
        self.assertEqual(self.cli(), 2)
        self.assertFalse(self.output.exists())

    def test_multiple_input_cli_and_filenames_with_spaces(self):
        self.source = self.root / "scan one.jsonl"
        self.output = self.root / "report one.json"
        self.write_records(observation())
        other = self.write_records(observation(), path=self.root / "scan two.jsonl")
        self.assertEqual(self.cli("--input", str(other)), 0)
        self.assertEqual(json.loads(self.output.read_text())["findings"][0]["occurrences"], 2)

    def test_non_positive_line_limit_rejected(self):
        for value in ("0", "-1", "bad"):
            with self.assertRaises(SystemExit) as error:
                self.cli("--max-line-bytes", value)
            self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
