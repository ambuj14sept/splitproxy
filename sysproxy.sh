#!/bin/bash
# Toggle the macOS system proxy (used by Safari, Chrome, most apps) to splitproxy.
# usage: ./sysproxy.sh on|off|status|check [network-service-name]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
[ -f "$HERE/.env" ] && set -a && . "$HERE/.env" && set +a
HTTP_LISTEN="${HTTP_LISTEN:-127.0.0.1:8080}"; SOCKS_LISTEN="${SOCKS_LISTEN:-127.0.0.1:1080}"
HP_HOST="${HTTP_LISTEN%:*}"; HP_PORT="${HTTP_LISTEN##*:}"
SP_HOST="${SOCKS_LISTEN%:*}"; SP_PORT="${SOCKS_LISTEN##*:}"

# Physical interface: NOT the default route (that is the VPN's utun when GlobalProtect is up).
phys_iface() {
  for i in $(ifconfig -l); do
    case "$i" in en*) ifconfig "$i" 2>/dev/null | grep -q 'inet ' && ifconfig "$i" | grep -q 'status: active' && { echo "$i"; return; };; esac
  done
  for i in $(ifconfig -l); do case "$i" in en*) ifconfig "$i" 2>/dev/null | grep -q 'inet ' && { echo "$i"; return; };; esac; done
}
IFACE="${DIRECT_IFACE:-auto}"; [ "$IFACE" = auto ] && IFACE="$(phys_iface)"
SVC="${2:-$(networksetup -listnetworkserviceorder | grep -B1 "Device: ${IFACE:-en0})" | head -1 | sed -E 's/^\([0-9]+\) //')}"
[ -z "$SVC" ] && { echo "could not determine network service; pass it as 2nd arg (see: networksetup -listallnetworkservices)"; exit 1; }

# Changing proxy settings needs admin rights on macOS; reading them does not.
# All changes go through ONE sudo call so the password is asked at most once.
asroot() {
  if [ "$(id -u)" = 0 ]; then sh -c "$1"
  else echo "(macOS asks for your password to change proxy settings)"; sudo sh -c "$1"; fi
}

case "${1:-}" in
  on)
    asroot "networksetup -setwebproxy '$SVC' $HP_HOST $HP_PORT &&
            networksetup -setsecurewebproxy '$SVC' $HP_HOST $HP_PORT &&
            networksetup -setsocksfirewallproxy '$SVC' $SP_HOST $SP_PORT &&
            networksetup -setproxybypassdomains '$SVC' localhost 127.0.0.1 '*.local' 169.254/16" \
      || { echo "could not change system proxy (admin rights needed). Use per-app setup, see README." >&2; exit 2; }
    echo "system proxy ON for '$SVC' -> http $HTTP_LISTEN, socks $SOCKS_LISTEN";;
  off)
    asroot "networksetup -setwebproxystate '$SVC' off &&
            networksetup -setsecurewebproxystate '$SVC' off &&
            networksetup -setsocksfirewallproxystate '$SVC' off" \
      || { echo "could not change system proxy (admin rights needed)." >&2; exit 2; }
    echo "system proxy OFF for '$SVC'";;
  check)
    # exit 0 if the system proxy already points at splitproxy, 1 otherwise (no admin needed)
    want_http="Enabled: Yes Server: $HP_HOST Port: $HP_PORT"
    want_socks="Enabled: Yes Server: $SP_HOST Port: $SP_PORT"
    got() { networksetup "$1" "$SVC" | awk '/^(Enabled|Server|Port):/{printf "%s %s ", $1, $2}' | sed 's/ $//'; }
    [ "$(got -getwebproxy)" = "$want_http" ] && [ "$(got -getsecurewebproxy)" = "$want_http" ] && [ "$(got -getsocksfirewallproxy)" = "$want_socks" ];;
  status)
    echo "service: $SVC"; networksetup -getwebproxy "$SVC"; networksetup -getsecurewebproxy "$SVC"; networksetup -getsocksfirewallproxy "$SVC";;
  *) echo "usage: $0 on|off|status|check [network-service-name]"; exit 1;;
esac
