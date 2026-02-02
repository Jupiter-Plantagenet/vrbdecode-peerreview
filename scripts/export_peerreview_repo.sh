#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PUBLIC_URL_DEFAULT="https://github.com/Jupiter-Plantagenet/vrbdecode-peerreview.git"

usage() {
  cat <<EOF
Usage: ./scripts/export_peerreview_repo.sh [--dest <path>] [--public-url <url>] [--branch <name>]

Exports a *code-only* peer-review repository from the private repo by copying a whitelist
of files/dirs and excluding papers and generated artifacts.

Defaults:
  --dest       ../vrbdecode-peerreview
  --public-url ${PUBLIC_URL_DEFAULT}
  --branch     main
EOF
}

DEST="../vrbdecode-peerreview"
PUBLIC_URL="${PUBLIC_URL_DEFAULT}"
BRANCH="main"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dest) DEST="$2"; shift 2 ;;
    --public-url) PUBLIC_URL="$2"; shift 2 ;;
    --branch) BRANCH="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

DEST_ABS="$(cd "$ROOT" && python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$DEST")"

echo "[export] private repo: $ROOT"
echo "[export] public repo:  $DEST_ABS"
echo "[export] public url:   $PUBLIC_URL"

if [[ ! -d "$DEST_ABS/.git" ]]; then
  echo "[export] cloning public repo..."
  if ! (export GIT_TERMINAL_PROMPT=0; git clone "$PUBLIC_URL" "$DEST_ABS"); then
    echo "[export] WARN: clone failed (repo may be private or auth required). Initializing local repo instead." >&2
    mkdir -p "$DEST_ABS"
    pushd "$DEST_ABS" >/dev/null
    git init >/dev/null
    git remote add origin "$PUBLIC_URL" >/dev/null 2>&1 || git remote set-url origin "$PUBLIC_URL"
    git checkout -B "$BRANCH" >/dev/null 2>&1 || true
    popd >/dev/null
  fi
fi

pushd "$DEST_ABS" >/dev/null
git fetch --all --prune >/dev/null 2>&1 || true
git checkout -B "$BRANCH" "origin/$BRANCH" >/dev/null 2>&1 || git checkout -B "$BRANCH" >/dev/null 2>&1 || true

# Clean public repo working tree (keeps .git); this prevents stale files from lingering.
git reset --hard >/dev/null
git clean -fdx >/dev/null
popd >/dev/null

STAGING="$(mktemp -d)"
cleanup() { rm -rf "$STAGING"; }
trap cleanup EXIT

copy_dir() {
  local rel="$1"
  if [[ -e "$ROOT/$rel" ]]; then
    mkdir -p "$(dirname "$STAGING/$rel")"
    rsync -a --delete \
      --exclude 'target/' \
      --exclude 'target_*/' \
      --exclude 'target_eval_release/' \
      --exclude 'eval/cache/' \
      --exclude 'eval/artifacts/' \
      --exclude 'eval/archive/' \
      --exclude 'eval/plots/' \
      --exclude 'eval/wrapped_proofs/' \
      --exclude 'eval/*.json' \
      --exclude 'eval/*.csv' \
      --exclude '*.bin' \
      --exclude '*.calldata' \
      --exclude '*.aux' --exclude '*.bbl' --exclude '*.blg' --exclude '*.fls' --exclude '*.fdb_latexmk' --exclude '*.out' --exclude '*.log' --exclude '*.spl' \
      --exclude '.env' --exclude '.env.*' --exclude '*.env' \
      --exclude '*.key' --exclude '*.pem' --exclude '*.p12' --exclude '*.pfx' \
      --exclude 'private/' \
      "$ROOT/$rel" "$STAGING/$rel"
  fi
}

copy_file() {
  local rel="$1"
  if [[ -f "$ROOT/$rel" ]]; then
    mkdir -p "$(dirname "$STAGING/$rel")"
    cp -p "$ROOT/$rel" "$STAGING/$rel"
  fi
}

# Whitelist: code + reproducibility only. NO paper/ directory.
copy_file "Cargo.toml"
copy_file "Cargo.lock"
copy_file "rust-toolchain.toml"
copy_file ".gitignore"
copy_file "ci.sh"
copy_file "REPRODUCIBILITY.md"
copy_file "TESTING.md"
copy_file "README.md"

copy_dir "spec/"
copy_dir "ref/"
copy_dir "vectors/"
copy_dir "vrbdecode-core/"
copy_dir "vrbdecode-zk/"
copy_dir "third_party/"
copy_dir "eval/"
copy_dir "scripts/"
copy_dir "repro/"

# Write a small marker to make it obvious this repo is export-built.
cat >"$STAGING/EXPORT_METADATA.txt" <<EOF
Exported from private repository.
- source: $ROOT
- time:   $(date -u +"%Y-%m-%dT%H:%M:%SZ")
- tool:   scripts/export_peerreview_repo.sh
EOF

# Sync staging to destination (excluding .git).
rsync -a --delete --exclude '.git' "$STAGING"/ "$DEST_ABS"/

echo "[export] completed. Next:"
echo "  cd \"$DEST_ABS\""
echo "  git status"
echo "  git add -A && git commit -m \"Update peer-review export\" && git push"
