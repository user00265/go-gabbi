# GOCACHE is not set here: recipes inherit it from the environment, and
# when it is unset Go uses its default cache directory.
export CGO_ENABLED := "0"

# List the recipes.
default:
    @just --list

# Run golangci-lint (v2 config in .golangci.yml).
lint:
    golangci-lint run

# Run the tests.
test:
    CGO_ENABLED=0 go test ./...

# Run every fuzz target for 30 seconds each.
fuzz:
    #!/usr/bin/env bash
    set -euo pipefail
    packages=$(go list ./...)
    for pkg in $packages; do
        targets=$(go test -list '^Fuzz' "$pkg")
        for target in $targets; do
            case "$target" in
                Fuzz*) echo "== $pkg $target"; go test -run '^$' -fuzz "^${target}\$" -fuzztime=30s -fuzzminimizetime=1s "$pkg" ;;
            esac
        done
    done

# Generate golden fixtures with the pinned tqsl container.
fixtures:
    @echo "Generate .tq5 fixtures: sh testdata/tq5/generate.sh EMPTY_OUTPUT_DIRECTORY"
    @echo "Generate .tq8 fixtures: sh testdata/tq8/generate.sh EMPTY_OUTPUT_DIRECTORY"

# Fail if the global gitignore hides any required path.
doctor:
    #!/usr/bin/env bash
    set -uo pipefail
    paths="go.mod justfile .golangci.yml .gitignore README.md LICENSE NOTICE doc.go testdata/ internal/ .github/"
    git check-ignore -v --no-index $paths
    status=$?
    case $status in
        0) echo "doctor: the paths above are ignored" >&2; exit 1 ;;
        1) echo "doctor: no required path is ignored" ;;
        *) echo "doctor: git check-ignore failed (exit $status)" >&2; exit 1 ;;
    esac
