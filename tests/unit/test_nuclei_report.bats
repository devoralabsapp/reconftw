#!/usr/bin/env bats

@test "offline Nuclei report Python regression suite" {
    local project_root
    project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
    run python3 "$project_root/tests/unit/test_nuclei_report.py"
    printf '%s\n' "$output"
    [ "$status" -eq 0 ]
}
