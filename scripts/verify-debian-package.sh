#!/bin/bash
# Run in a clean, disposable Debian 13 container.
set -euo pipefail

package=$(realpath "${1:?Specify the package to install}")
revision="${2:?Specify the Git revision used to build the package}"
test "$(dpkg-deb -f "$package" Package)" = justconnect
test "$(dpkg-deb -f "$package" Architecture)" = amd64

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y "$package"
test -z "$(dpkg --verify justconnect)"
test -x /usr/bin/JustConnect
cmp /usr/share/icons/hicolor/scalable/apps/JustConnect.svg "$(dirname "$0")/../resource/icon.svg"
helper=/usr/libexec/justconnect-network-helper
test -x "$helper"
test "$(stat -c '%u:%g:%a' "$helper")" = '0:0:755'
policy=/usr/share/polkit-1/actions/org.justconnect.network-helper.policy
grep -Fq "<annotate key=\"org.freedesktop.policykit.exec.path\">$helper</annotate>" "$policy"
identity=$("$helper" --version)
grep -F "\"revision\":\"$revision\"" <<< "$identity"
grep -Fq '"source_state":"clean"' <<< "$identity"
report=$(/usr/bin/JustConnect --core-self-test)
grep -F '"ok":true' <<< "$report"
grep -Fq "\"revision\":\"$revision\"" <<< "$report"
grep -Fq '"source_state":"clean"' <<< "$report"

DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends xvfb xauth xdotool x11-utils
home=$(mktemp -d)
trap 'rm -rf "$home"' EXIT
chown nobody:nogroup "$home"
/usr/sbin/runuser -u nobody -- env HOME="$home" XDG_CONFIG_HOME="$home/config" XDG_DATA_HOME="$home/data" \
    XDG_CACHE_HOME="$home/cache" QT_QPA_PLATFORM=xcb xvfb-run -a bash -ec '
        /usr/bin/JustConnect &
        pid=$!
        trap "kill $pid 2>/dev/null || true" EXIT
        window=$(timeout 15s xdotool search --sync --onlyvisible --pid "$pid" --limit 1)
        desktop_id=$(xprop -notype -id "$window" _GTK_APPLICATION_ID | cut -d\" -f2)
        test -f "/usr/share/applications/$desktop_id.desktop"
        kill -TERM "$pid"
        wait "$pid"
    '
