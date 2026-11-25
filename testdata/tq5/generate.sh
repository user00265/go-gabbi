#!/bin/sh
# Regenerate only with disposable, locally generated keys. No network service is contacted.
set -eu
if [ "$#" -ne 1 ] || [ ! -d "$1" ] || [ -n "$(ls -A "$1")" ]; then
    printf 'usage: sh testdata/tq5/generate.sh EMPTY_OUTPUT_DIRECTORY\n' >&2
    exit 2
fi
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
output=$(CDPATH= cd -- "$1" && pwd)
podman build -t go-gabbi-tq5-fixture -f "$root/testdata/tq5/Containerfile" "$root/testdata/tq5"
podman run --rm --network=none --userns=keep-id -v "$root/testdata/tq5:/fixtures:ro,Z" -v "$output:/output:Z" go-gabbi-tq5-fixture sh /fixtures/run.sh
