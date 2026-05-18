#!/usr/bin/env bash
# tvault installer — detects OS/arch, downloads the matching release binary,
# verifies its SHA256, and installs it.
#
# Optional environment variables:
#   TVAULT_VERSION       Pin a specific tag (e.g. v0.6.0). Defaults to the
#                        latest published release.
#   TVAULT_INSTALL_DIR   Override install location. Defaults to /usr/local/bin
#                        if writable and tvault is already there, else
#                        $HOME/.local/bin.
set -euo pipefail

REPO="c-lgrant/tvault"
BINARY="tvault"

# curl_retry — call curl with up to 3 attempts and 2-second backoff. Args are
# passed through verbatim. Fails loudly only after all retries are exhausted.
curl_retry() {
  local attempt=1
  while [ "$attempt" -le 3 ]; do
    if curl -fsSL "$@"; then
      return 0
    fi
    if [ "$attempt" -lt 3 ]; then
      echo "curl failed (attempt ${attempt}/3); retrying in 2s…" >&2
      sleep 2
    fi
    attempt=$((attempt + 1))
  done
  echo "curl failed after 3 attempts" >&2
  return 1
}

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac
case "$os" in
  linux|darwin) ;;
  *) echo "unsupported OS: $os" >&2; exit 1 ;;
esac

if [ -n "${TVAULT_VERSION:-}" ]; then
  tag="$TVAULT_VERSION"
else
  # Don't use `grep -m1` here — closing the pipe early gives curl SIGPIPE
  # (exit 23 "Failure writing output to destination") under pipefail.
  tag="$(curl_retry "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -1 | cut -d'"' -f4)"
fi
if [ -z "$tag" ]; then
  echo "could not determine the release tag" >&2; exit 1
fi

asset="${BINARY}_${tag}_${os}_${arch}.tar.gz"
base="https://github.com/${REPO}/releases/download/${tag}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading ${asset}…"
curl_retry "${base}/${asset}" -o "${tmp}/${asset}"
curl_retry "${base}/checksums.txt" -o "${tmp}/checksums.txt"

echo "Verifying checksum…"
( cd "$tmp" && grep " ${asset}\$" checksums.txt | sha256sum -c - )

tar -xzf "${tmp}/${asset}" -C "$tmp"

if [ -n "${TVAULT_INSTALL_DIR:-}" ]; then
  dest="$TVAULT_INSTALL_DIR"
  mkdir -p "$dest"
elif [ -w /usr/local/bin ] && [ -e /usr/local/bin/${BINARY} ]; then
  dest="/usr/local/bin"
else
  dest="${HOME}/.local/bin"
  mkdir -p "$dest"
fi
install -m 0755 "${tmp}/${BINARY}" "${dest}/${BINARY}"

echo "Running self-test…"
if ! "${dest}/${BINARY}" version; then
  echo "self-test failed: ${dest}/${BINARY} version exited non-zero" >&2
  exit 1
fi

echo "Installed ${BINARY} ${tag} to ${dest}/${BINARY}"

case ":${PATH}:" in
  *":${dest}:"*) ;;
  *)
    echo
    echo "NOTE: ${dest} is not on your \$PATH."
    echo "Add this line to your shell rc (~/.bashrc, ~/.zshrc, etc.):"
    echo
    echo "    export PATH=\"${dest}:\$PATH\""
    echo
    ;;
esac
