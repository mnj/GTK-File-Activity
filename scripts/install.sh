#!/bin/sh
# SPDX-License-Identifier: MIT
# Installs GTK File Activity from an unpacked release (or a source checkout
# after `cargo build --release`). Run as root for a system-wide prefix.
#
#   sudo ./install.sh              # to /usr/local
#   sudo PREFIX=/usr ./install.sh  # to /usr, which also installs the polkit policy
set -eu

prefix="${PREFIX:-/usr/local}"
here="$(cd "$(dirname "$0")" && pwd)"
bin="$here/gtk-file-activity"
[ -x "$bin" ] || bin="$here/../target/release/gtk-file-activity"
data="$here/data"
[ -d "$data" ] || data="$here/../data"

install -Dm755 "$bin" "$prefix/bin/gtk-file-activity"
install -Dm644 "$data/local.gtk.FileActivity.desktop" \
    "$prefix/share/applications/local.gtk.FileActivity.desktop"

# The policy names the executable by absolute path, so it only matches /usr/bin.
if [ "$prefix" = "/usr" ]; then
    install -Dm644 "$data/local.gtk.FileActivity.policy" \
        /usr/share/polkit-1/actions/local.gtk.FileActivity.policy
else
    echo "Installed under $prefix: authentication will use pkexec's generic prompt."
    echo "Use PREFIX=/usr to also install the polkit policy."
fi
