#!/usr/bin/env bash
# sync-shared.sh — vendor a pinned tag of supabase-shared into an app repo.
#
# Usage (from the app repo):
#   path/to/sync-shared.sh <tag> <dest>
#   e.g. sync-shared.sh 0.1.0 supabase/functions/_shared/portfolio
#
# Shallow-clones <tag> of the repo into a temp dir, replaces <dest> with its
# src/ tree, and writes <dest>/VERSION (tag, commit, repo, date). Commit the
# result: the self-hosted edge runtime should never fetch a private remote
# import at boot, so apps run the vendored copy.
#
# Env:
#   SUPABASE_SHARED_REPO  clone URL (default https://github.com/Cliefden/supabase-shared.git;
#                         a local path works too, e.g. for testing an unpushed tag)
set -euo pipefail

usage() {
  echo "usage: $(basename "$0") <tag> <dest supabase/functions/_shared/portfolio>" >&2
  exit 2
}

[[ $# -eq 2 ]] || usage
TAG="$1"
DEST="$2"
REPO="${SUPABASE_SHARED_REPO:-https://github.com/Cliefden/supabase-shared.git}"

[[ -n "$TAG" && -n "$DEST" ]] || usage
case "$DEST" in
  /|.|..|"$HOME") echo "refusing to sync into '$DEST'" >&2; exit 1 ;;
esac

# Only replace a directory this script created (it has a VERSION file) or an empty one.
if [[ -e "$DEST" ]]; then
  if [[ ! -d "$DEST" ]]; then
    echo "$DEST exists and is not a directory" >&2; exit 1
  fi
  if [[ ! -f "$DEST/VERSION" && -n "$(ls -A "$DEST")" ]]; then
    echo "$DEST is not empty and has no VERSION file — not a vendored supabase-shared copy; refusing to overwrite" >&2
    exit 1
  fi
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$TAG" "$REPO" "$TMP/repo"
COMMIT="$(git -C "$TMP/repo" rev-parse HEAD)"

[[ -d "$TMP/repo/src" ]] || { echo "tag $TAG has no src/ directory" >&2; exit 1; }

rm -rf "$DEST"
mkdir -p "$DEST"
cp -R "$TMP/repo/src/." "$DEST/"

cat > "$DEST/VERSION" <<EOF
supabase-shared $TAG
commit: $COMMIT
repo: $REPO
synced: $(date -u +%Y-%m-%dT%H:%M:%SZ)

Vendored copy — do not edit here. Change supabase-shared, tag a release, and
re-run: sync-shared.sh <tag> $DEST
EOF

echo "synced supabase-shared $TAG ($COMMIT) into $DEST"
