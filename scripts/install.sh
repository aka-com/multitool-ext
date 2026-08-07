#!/usr/bin/env bash
set -euo pipefail

# Install the built `aka` CLI into a user-local directory already on PATH.
#
#   bash scripts/install.sh              use newest existing debug/release binary
#   bash scripts/install.sh --build      build release, then install
#   bash scripts/install.sh --build --debug
#                                        build debug, then install
#
# Destination (first match wins):
#   INSTALL_DIR   exact directory for the binary
#   PREFIX        install to $PREFIX/bin (default PREFIX=$HOME/.local → ~/.local/bin)
#
# Prompts Y/n before installing (Enter accepts the default Yes). The prompt
# reports whether an existing aka file or symlink would be replaced.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
repo_root="$(cd "$script_dir/.." >/dev/null && pwd)"
cd "$repo_root"

profile=release
do_build=0

usage() {
  cat <<'EOF'
Usage: scripts/install.sh [options]

Install the aka CLI into a user-local PATH directory.

By default this does not build. It installs the most recently modified binary
among target/debug/aka and target/release/aka (timestamps shown).

Options:
  --build       Build before install (default profile: release)
  --debug       With --build: build target/debug/aka
  -h, --help    Show this help

Environment:
  INSTALL_DIR   Directory for the binary (default: $PREFIX/bin)
  PREFIX        Install prefix (default: $HOME/.local)
EOF
}

for arg in "$@"; do
  case "$arg" in
    --debug) profile=debug ;;
    --build) do_build=1 ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $arg" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -n "${INSTALL_DIR:-}" ]]; then
  install_dir="$INSTALL_DIR"
else
  prefix="${PREFIX:-$HOME/.local}"
  install_dir="$prefix/bin"
fi

debug_src="$repo_root/target/debug/aka"
release_src="$repo_root/target/release/aka"
dest="$install_dir/aka"

# Format mtime for display; empty string if missing.
mtime_display() {
  local path="$1"
  if [[ -f "$path" ]]; then
    # macOS date(1) uses -r; GNU date uses -d @epoch. Prefer stat+date that works on macOS.
    if stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S %z' "$path" 2>/dev/null; then
      return 0
    fi
    if mod_epoch="$(stat -c '%Y' "$path" 2>/dev/null)"; then
      date -d "@$mod_epoch" '+%Y-%m-%d %H:%M:%S %z' 2>/dev/null || date -r "$mod_epoch" '+%Y-%m-%d %H:%M:%S %z'
      return 0
    fi
    echo "unknown"
  else
    echo "(missing)"
  fi
}

# Epoch mtime for comparison; empty if missing.
mtime_epoch() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    return 0
  fi
  if stat -f '%m' "$path" 2>/dev/null; then
    return 0
  fi
  stat -c '%Y' "$path" 2>/dev/null || true
}

echo "Existing binaries:"
echo "  debug:   $debug_src"
echo "           $(mtime_display "$debug_src")"
echo "  release: $release_src"
echo "           $(mtime_display "$release_src")"

if [[ "$do_build" -eq 1 ]]; then
  echo
  echo "Building aka ($profile)..."
  if [[ "$profile" == release ]]; then
    cargo build --release -p multitool
  else
    cargo build -p multitool
  fi
  src="$repo_root/target/$profile/aka"
else
  debug_m="$(mtime_epoch "$debug_src")"
  release_m="$(mtime_epoch "$release_src")"

  if [[ -z "${debug_m:-}" && -z "${release_m:-}" ]]; then
    echo "error: no existing binary found at:" >&2
    echo "  $debug_src" >&2
    echo "  $release_src" >&2
    echo "hint: build with \`cargo build --release -p multitool\` or re-run with --build" >&2
    exit 1
  fi

  if [[ -n "${debug_m:-}" && -z "${release_m:-}" ]]; then
    src="$debug_src"
    profile=debug
  elif [[ -z "${debug_m:-}" && -n "${release_m:-}" ]]; then
    src="$release_src"
    profile=release
  elif [[ "$debug_m" -ge "$release_m" ]]; then
    src="$debug_src"
    profile=debug
  else
    src="$release_src"
    profile=release
  fi

  echo
  echo "Using most recent binary: $profile ($(mtime_display "$src"))"
fi

if [[ ! -f "$src" ]]; then
  echo "error: binary not found: $src" >&2
  if [[ "$do_build" -eq 0 ]]; then
    echo "hint: build with \`scripts/install.sh --build\` or \`cargo build --release -p multitool\`" >&2
  fi
  exit 1
fi

if [[ ! -d "$install_dir" ]]; then
  echo "Creating $install_dir"
  mkdir -p "$install_dir"
fi

if [[ ! -w "$install_dir" ]]; then
  echo "error: install directory is not writable: $install_dir" >&2
  exit 1
fi

existing_note="no existing aka there"
if [[ -e "$dest" || -L "$dest" ]]; then
  if [[ -L "$dest" ]]; then
    target="$(readlink "$dest" || true)"
    if [[ -n "$target" ]]; then
      existing_note="replacing existing symlink → $target"
    else
      existing_note="replacing existing symlink"
    fi
  elif [[ -f "$dest" ]]; then
    existing_note="replacing existing binary"
  else
    existing_note="replacing existing path ($(file -b "$dest" 2>/dev/null || echo "not a regular file"))"
  fi
fi

path_note=""
case ":$PATH:" in
  *":$install_dir:"*) ;;
  *) path_note=" (warning: $install_dir is not on PATH)" ;;
esac

echo
echo "Install aka ($profile) to $dest$path_note"
echo "  source:  $src"
echo "  dest:    $existing_note"
echo
printf "Proceed? [Y/n] "
read -r answer || true
case "${answer:-Y}" in
  Y | y | yes | YES | Yes | "") ;;
  *)
    echo "Aborted."
    exit 1
    ;;
esac

install -m 755 "$src" "$dest"
echo "Installed $dest"

if command -v aka >/dev/null 2>&1; then
  resolved="$(command -v aka)"
  if [[ "$resolved" == "$dest" ]]; then
    echo "on PATH as: $resolved"
  else
    echo "note: \`command -v aka\` resolves to $resolved (not $dest)"
  fi
fi
