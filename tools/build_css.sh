#!/usr/bin/env bash
# Compile web/static/src/input.css -> web/static/css/app.css using the
# standalone tailwindcss CLI (no Node/npm required). The built CSS is
# committed, so this script only needs to be re-run when input.css changes
# or a template introduces a class Tailwind hasn't generated yet.
set -euo pipefail
cd "$(dirname "$0")/.."

BIN="tools/.bin/tailwindcss"
NPM_DIR="tools/.bin/tw-npm"

mkdir -p web/static/css

# 1) Prefer the standalone binary - no Node needed, what a normal dev machine
#    or CI runner should end up using.
if [ ! -x "$BIN" ]; then
  mkdir -p tools/.bin
  os="$(uname -s)"
  arch="$(uname -m)"
  case "${os}-${arch}" in
    Darwin-arm64) asset="tailwindcss-macos-arm64" ;;
    Darwin-x86_64) asset="tailwindcss-macos-x64" ;;
    Linux-x86_64) asset="tailwindcss-linux-x64" ;;
    Linux-aarch64|Linux-arm64) asset="tailwindcss-linux-arm64" ;;
    *) asset="" ;;
  esac
  if [ -n "$asset" ]; then
    url="https://github.com/tailwindlabs/tailwindcss/releases/latest/download/${asset}"
    echo "Fetching standalone tailwindcss (${asset})..."
    if curl -fsSL --retry 2 "$url" -o "$BIN"; then
      chmod +x "$BIN"
    else
      echo "Standalone binary download failed (network/firewall?) - falling back to npm." >&2
      rm -f "$BIN"
    fi
  fi
fi

if [ -x "$BIN" ]; then
  echo "Building with the standalone tailwindcss CLI..."
  "$BIN" -i web/static/src/input.css -o web/static/css/app.css --minify
  echo "Built web/static/css/app.css"
  exit 0
fi

# 2) Fallback: npm-installed tailwindcss in a scratch, gitignored directory.
#    Only used when the standalone binary can't be fetched (e.g. this repo's
#    sandboxed CI/dev environment blocks GitHub's release-asset host while
#    still allowing the npm registry). Needs Node + npm on PATH.
echo "No standalone binary available - falling back to npm (needs Node/npm)." >&2
if ! command -v npm >/dev/null 2>&1; then
  echo "npm not found either. Install Node, or place a tailwindcss binary at ${BIN}." >&2
  exit 1
fi
if [ ! -d "$NPM_DIR/node_modules/tailwindcss" ]; then
  mkdir -p "$NPM_DIR"
  (cd "$NPM_DIR" && [ -f package.json ] || npm init -y >/dev/null)
  (cd "$NPM_DIR" && npm install --no-audit --no-fund tailwindcss@4 @tailwindcss/cli@4)
fi
NODE_PATH="$(pwd)/${NPM_DIR}/node_modules" node "$(pwd)/${NPM_DIR}/node_modules/.bin/tailwindcss" \
  -i web/static/src/input.css -o web/static/css/app.css --minify
echo "Built web/static/css/app.css (via npm fallback)"
