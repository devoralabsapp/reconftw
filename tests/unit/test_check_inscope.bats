#!/usr/bin/env bats

load '../helpers/common'

setup() {
    setup_recon_env
    cd "${BATS_TEST_TMPDIR:?bats-core 1.5+ is required}"
    printf 'a.example.com\noutside.test\n' > input.txt
    inscope() { grep -F '.example.com' || true; }
    export -f inscope
}

@test "check_inscope publishes filtered results with private permissions" {
    check_inscope input.txt
    [ "$(cat input.txt)" = 'a.example.com' ]
    [ "$(stat -c %a input.txt)" = 600 ]
    [ "$(find . -name '*.scope.*' | wc -l)" -eq 0 ]
}

@test "check_inscope preserves the original on filter failure" {
    inscope() { printf 'partial result\n'; return 1; }
    export -f inscope
    cp input.txt expected.txt
    run check_inscope input.txt
    [ "$status" -ne 0 ]
    cmp input.txt expected.txt
    [ "$(find . -name '*.scope.*' | wc -l)" -eq 0 ]
}

@test "check_inscope accepts a successful empty result" {
    inscope() { cat >/dev/null; }
    export -f inscope
    check_inscope input.txt
    [ ! -s input.txt ]
}

@test "check_inscope refuses symlinks and missing or directory input" {
    cp input.txt expected.txt
    ln -s input.txt linked.txt
    for path in linked.txt missing.txt . ''; do
        run check_inscope "$path"
        [ "$status" -ne 0 ]
    done
    cmp input.txt expected.txt
}

@test "check_inscope does not touch the old predictable temp path" {
    printf 'unrelated\n' > unrelated.txt
    ln -s unrelated.txt input.txt_tmp
    check_inscope input.txt
    [ "$(cat unrelated.txt)" = unrelated ]
    [ -L input.txt_tmp ]
}

@test "check_inscope handles filenames with spaces and leading dashes" {
    mv input.txt './-scope input.txt'
    check_inscope '-scope input.txt'
    [ "$(cat -- '-scope input.txt')" = 'a.example.com' ]
}

@test "check_inscope cleans up and preserves input when publication fails" {
    cp input.txt expected.txt
    mv() { return 1; }
    export -f mv
    run check_inscope input.txt
    [ "$status" -ne 0 ]
    cmp input.txt expected.txt
    [ "$(find . -name '*.scope.*' | wc -l)" -eq 0 ]
}

@test "check_inscope preserves input when staging cannot be created" {
    cp input.txt expected.txt
    mktemp() { return 1; }
    export -f mktemp
    run check_inscope input.txt
    [ "$status" -ne 0 ]
    cmp input.txt expected.txt
}
