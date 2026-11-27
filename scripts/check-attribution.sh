#!/bin/sh
# Reject AI co-author attribution in commit messages.
#   check-attribution.sh <commit-msg-file>     (git commit-msg hook)
#   check-attribution.sh --range <a>..<b>      (CI: every commit in a range)
set -eu

PATTERN='^[[:space:]]*co-authored-by:.*(claude|anthropic)|noreply@anthropic\.com|generated with \[?claude code'

if [ "${1:-}" = "--range" ]; then
    bad=0
    for c in $(git rev-list "$2"); do
        if git log -1 --format='%B%n%an <%ae>%n%cn <%ce>' "$c" | grep -qiE "$PATTERN"; then
            echo "commit $(git log -1 --format='%h %s' "$c") carries AI attribution" >&2
            bad=1
        fi
    done
    exit "$bad"
fi

if grep -v '^#' "$1" | grep -qiE "$PATTERN"; then
    echo "commit message carries an AI co-author/attribution line; remove it (see scripts/check-attribution.sh)" >&2
    exit 1
fi
