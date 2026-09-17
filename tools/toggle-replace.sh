#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# toggle-replace.sh — flip every adopting service's go.mod between
# "local-path replace" (dev) and "tagged require" (prod) for the
# platform-shared module.
#
# Why this exists
# ───────────────
# When the platform-shared/outbox package was added (June 2026), each
# adopting Go service needed `replace github.com/dogukanturhal/platform-shared
# => ../../../platform-shared` in its go.mod so local dev would build
# against the just-edited package. These local replace directives MUST
# NOT ship to prod — they don't resolve in CI/builder containers.
#
# Run modes
# ─────────
#   ./toggle-replace.sh release   — strips replace directives, pins to TAG
#   ./toggle-replace.sh dev       — restores replace directives
#   ./toggle-replace.sh check     — exits 1 if any service still has the
#                                    local replace (CI guard)
#
# The TAG to pin is read from VERSION.txt at the top of platform-shared.
# Today it's v0.3.0 (bumped when outbox shipped). Update VERSION when
# you cut a new tag and re-run `release` mode.
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
SHARED_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION_FILE="$SHARED_ROOT/VERSION.txt"

if [[ ! -f "$VERSION_FILE" ]]; then
    echo "missing $VERSION_FILE — create it with the tag (e.g. echo v0.3.1 > VERSION.txt)" >&2
    exit 2
fi
TAG="$(<"$VERSION_FILE")"
MODULE="github.com/dogukanturhal/platform-shared"
LOCAL_PATH_PATTERN='\.\./.*platform-shared'

# Adopting services — keep in sync as new services adopt platform-shared/outbox.
# Use absolute paths because each service lives in a different parent repo.
SERVICES=(
    "/home/dogukanturhal/projects/example-suite/platform-services/billing"
    "/home/dogukanturhal/projects/example-suite/platform-services/domain-management"
    "/home/dogukanturhal/projects/example-suite/platform-services/integration-hub"
    "/home/dogukanturhal/projects/platform-engagement/services/marketing-automation"
    "/home/dogukanturhal/projects/platform-engagement/services/notification-service"
)

usage() {
    cat <<EOF
Usage: $0 [release|dev|check]

  release   strip 'replace ${MODULE} => ../../../platform-shared' from each
            service's go.mod; pin require to ${TAG}; run 'go mod tidy'.

  dev       restore the local replace directives + run 'go mod tidy'.

  check     verify NO service has the local replace (CI guard). Exits 1
            on first violation.

Adopting services (auto-updated when new adoption lands):
$(printf '  %s\n' "${SERVICES[@]}")
EOF
    exit "$1"
}

if [[ $# -ne 1 ]]; then usage 1; fi
MODE="$1"

# Heredoc used only by the dev path — appended verbatim.
local_replace_block() {
    cat <<EOF

// Local platform-shared for outbox package (toggle-replace.sh dev).
// DO NOT COMMIT THIS LINE — strip with toggle-replace.sh release before
// pushing to a deploy branch. CI guard: toggle-replace.sh check.
replace ${MODULE} => ${1}
EOF
}

# Compute the relative path from each service to platform-shared. The
# layouts in this monorepo are not uniform — some services live four
# levels deep, others five — so we resolve at runtime rather than
# hard-coding a single "../../../".
relative_to_shared() {
    local from="$1"
    python3 -c "import os.path,sys; print(os.path.relpath('$SHARED_ROOT', '$from'))"
}

# ─────────────────────────────────────────────────────────────────────────────
# Per-service operations
# ─────────────────────────────────────────────────────────────────────────────

# strip_replace removes ANY existing replace line for the platform-shared
# module (idempotent). Returns 0 if it changed anything, 1 otherwise.
strip_replace() {
    local file="$1"
    if grep -qE "^replace[[:space:]]+${MODULE//./\\.}[[:space:]]+=>" "$file"; then
        # Use sed to delete the matching replace line + any preceding
        # comment-only lines that begin with `// Local platform-shared`.
        python3 - "$file" <<'PY'
import re, sys
path = sys.argv[1]
src = open(path).read()
# Strip optional comment block that introduces the local replace + the
# replace line itself + the trailing blank line.
pattern = re.compile(
    r'(?:\n//[^\n]*\n)*'                                   # optional leading comments
    r'replace\s+gitlab\.hexxlock\.com/hexxlock/platform-shared\s+=>\s+\S+\n',
    re.MULTILINE,
)
new = pattern.sub('\n', src)
# Collapse triple-blank-lines that result from the strip.
new = re.sub(r'\n{3,}', '\n\n', new)
open(path, 'w').write(new)
PY
        return 0
    fi
    return 1
}

# pin_require ensures the require block has `MODULE TAG` (replacing any
# existing version pin to MODULE).
pin_require() {
    local file="$1" tag="$2"
    python3 - "$file" "$tag" <<'PY'
import re, sys
path, tag = sys.argv[1], sys.argv[2]
src = open(path).read()
# In any 'require ( ... )' block, ensure exactly one MODULE line at the
# pinned version. For now we only adjust the line if it already exists —
# adding a new require entry from scratch is unusual (the service is
# already using platform-shared by definition; the entry is there).
pattern = re.compile(
    r'(gitlab\.hexxlock\.com/hexxlock/platform-shared)\s+v\S+',
)
new = pattern.sub(rf'\1 {tag}', src)
open(path, 'w').write(new)
PY
}

# add_replace appends a local replace directive (idempotent — strips
# any existing one first to avoid duplicates).
add_replace() {
    local file="$1" path="$2"
    strip_replace "$file" || true
    {
        echo ""
        echo "// Local platform-shared for outbox package (toggle-replace.sh dev)."
        echo "// DO NOT COMMIT THIS LINE — strip with toggle-replace.sh release before"
        echo "// pushing to a deploy branch. CI guard: toggle-replace.sh check."
        echo "replace ${MODULE} => ${path}"
    } >>"$file"
}

# ─────────────────────────────────────────────────────────────────────────────
# Modes
# ─────────────────────────────────────────────────────────────────────────────

case "$MODE" in
    release)
        echo "Pinning ${MODULE} to ${TAG} across ${#SERVICES[@]} services..."
        for svc in "${SERVICES[@]}"; do
            gomod="$svc/go.mod"
            if [[ ! -f "$gomod" ]]; then
                echo "  skip (no go.mod): $svc"; continue
            fi
            printf "  %s ... " "$svc"
            stripped=0; strip_replace "$gomod" && stripped=1 || true
            pin_require "$gomod" "$TAG"
            (cd "$svc" && go mod tidy >/dev/null 2>&1 || true)
            if (( stripped )); then echo "stripped + pinned"; else echo "pinned"; fi
        done
        echo "Done. Verify with: $0 check"
        ;;

    dev)
        echo "Restoring local replace directives across ${#SERVICES[@]} services..."
        for svc in "${SERVICES[@]}"; do
            gomod="$svc/go.mod"
            if [[ ! -f "$gomod" ]]; then
                echo "  skip (no go.mod): $svc"; continue
            fi
            rel="$(relative_to_shared "$svc")"
            printf "  %s -> %s ... " "$svc" "$rel"
            add_replace "$gomod" "$rel"
            (cd "$svc" && go mod tidy >/dev/null 2>&1 || true)
            echo "ok"
        done
        echo "Done. Local-path replace directives in place."
        ;;

    check)
        violations=0
        for svc in "${SERVICES[@]}"; do
            gomod="$svc/go.mod"
            if [[ ! -f "$gomod" ]]; then continue; fi
            if grep -qE "^replace[[:space:]]+${MODULE//./\\.}[[:space:]]+=>\s+${LOCAL_PATH_PATTERN}" "$gomod"; then
                echo "VIOLATION: $gomod still has local-path replace" >&2
                violations=$((violations + 1))
            fi
        done
        if (( violations > 0 )); then
            echo "$violations service(s) still have local replace — run '$0 release' before deploying" >&2
            exit 1
        fi
        echo "OK: no local-path replace directives in any adopting service."
        ;;

    *) usage 1 ;;
esac
