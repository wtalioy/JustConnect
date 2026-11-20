#!/bin/sh
# Install the bundled privileged network helper (libexec/justconnect-network-helper)
# to /usr/local/libexec together with its polkit action, so automatic (TUN)
# routing can request administrator privileges.
#
# The helper must live in a root-owned system directory: pkexec-eligible
# programs are only honored when root owns every path component, and a helper
# inside an extracted archive keeps the extractor's ownership. There is no
# in-place promotion of the shipped copy; the application also refuses to
# launch helpers from unpacked package trees (see build-linux.md).
#
# Usage:
#   sudo ./setup-network-helper.sh   install the helper plus the polkit action
set -eu

die() { echo "setup-network-helper: $*" >&2; exit 1; }

package="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
helper="$package/libexec/justconnect-network-helper"
policy="$package/share/polkit-1/actions/org.justconnect.network-helper.policy"
system_helper="/usr/local/libexec/justconnect-network-helper"
system_policy="/usr/share/polkit-1/actions/org.justconnect.network-helper.policy"

[ "$(id -u)" = 0 ] || die "needs root to install into the system directories: run 'sudo $0'"
[ -f "$helper" ] || die "missing helper: $helper"

install -D -o root -g root -m 0755 "$helper" "$system_helper"
if [ -f "$policy" ]; then
    install -D -o root -g root -m 0644 "$policy" "$system_policy"
else
    echo "setup-network-helper: $policy is missing; pkexec falls back to its generic prompt" >&2
fi

# The installed copy — not the shipped one — is what pkexec will execute, so
# verify its ownership and permissions after the install.
owner="$(stat -c '%U:%G' "$system_helper")"
mode="$(stat -c '%a' "$system_helper")"
[ "$owner" = "root:root" ] || die "the installed helper is $owner-owned; pkexec requires root:root"
[ "$mode" = "755" ] || die "the installed helper has mode $mode; expected 755"
[ -x "$system_helper" ] || die "the installed helper is not executable"

echo "Installed the network helper for system-wide use:"
ls -l "$system_helper"
echo
echo "Rerun this script after every package update so the installed helper"
echo "matches the application's helper protocol."

"$system_helper" --version
echo "The helper above reports its identity; automatic routing can now request administrator privileges."
