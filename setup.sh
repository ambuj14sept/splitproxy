#!/bin/bash
# One-shot install / uninstall for splitproxy.
#   ./setup.sh install     start at login, keep alive, point the Mac's system proxy at it
#   ./setup.sh uninstall   undo all of the above
#   ./setup.sh status      show what is installed and whether the proxy is healthy
#   ./setup.sh test        run the routing self-test against a running proxy
set -euo pipefail
trap 'printf "  \033[31m✘\033[0m setup.sh failed at line %s: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
[ -f .env ] && set -a && . ./.env && set +a
HTTP_LISTEN="${HTTP_LISTEN:-127.0.0.1:8080}"
LABEL=com.local.splitproxy
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
RUNTIME="$HOME/.splitproxy"
LOG="$RUNTIME/logs/splitproxy.log"

ok()   { printf '  \033[32m✔\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
fail() { printf '  \033[31m✘\033[0m %s\n' "$*"; exit 1; }
step() { printf '\n\033[1m%s\033[0m\n' "$*"; }

proxy_up() { curl -s -m 2 -o /dev/null "http://$HTTP_LISTEN/status"; }
vpn_iface() { curl -s -m 2 "http://$HTTP_LISTEN/status" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("vpn_iface") or "")' 2>/dev/null || true; }

run_test() {
  step "Routing self-test"
  proxy_up || fail "proxy is not answering on $HTTP_LISTEN"
  local vi; vi="$(vpn_iface)"
  if [ -n "$vi" ]; then ok "GlobalProtect interface detected: $vi"
  else warn "GlobalProtect interface NOT detected. Connect GlobalProtect for the VPN test to mean anything."; fi
  local first_vpn; first_vpn="$(printf '%s' "${VPN_HOSTS:-}" | tr ', ' '\n\n' | grep -v '^\*' | grep -v '^\.' | grep -v '/' | head -1)"
  if [ -n "$first_vpn" ]; then
    code=$(curl -s -m 15 -o /dev/null -w '%{http_code}' -x "http://$HTTP_LISTEN" "https://$first_vpn/" || true)
    [ "$code" != 000 ] && ok "VPN host  $first_vpn -> HTTP $code" || warn "VPN host  $first_vpn -> no response (is GlobalProtect connected?)"
  fi
  code=$(curl -s -m 15 -o /dev/null -w '%{http_code}' -x "http://$HTTP_LISTEN" "https://www.youtube.com/" || true)
  [ "$code" != 000 ] && ok "direct    www.youtube.com -> HTTP $code" || warn "direct    www.youtube.com -> no response (GlobalProtect may block bypass traffic)"
  echo; echo "  Per-connection routing is in: $LOG"
}

case "${1:-}" in
  install)
    step "1/5 Checks"
    command -v python3 >/dev/null || fail "python3 not found (brew install python)"
    [ -f .env ] || { cp .env.example .env; warn "created .env from .env.example; edit VPN_HOSTS later if needed"; }
    ok "python3: $(python3 --version)"; ok "config: $HERE/.env"
    for spec in "HTTP_LISTEN=$HTTP_LISTEN" "SOCKS_LISTEN=${SOCKS_LISTEN:-127.0.0.1:1080}"; do
      var="${spec%%=*}"; port="${spec##*:}"
      owner="$( (lsof -nP -iTCP:"$port" -sTCP:LISTEN -Fc 2>/dev/null || true) | sed -n 's/^c//p' | head -1)"
      if [ -n "$owner" ] && [ "$owner" != Python ]; then
        fail "port $port is in use by '$owner'; change $var in .env to a free port"
      fi
      ok "port $port free ($var)"
    done

    step "2/5 Install login item (LaunchAgent, auto-restart)"
    ./install-launchd.sh >/dev/null
    ok "$PLIST"
    ok "runtime copy: $RUNTIME (re-run install after editing .env)"

    step "3/5 Wait for the proxy to come up"
    for i in $(seq 1 20); do proxy_up && break; sleep 0.5; done
    proxy_up || fail "proxy did not start; see $LOG and: launchctl print gui/\$(id -u)/$LABEL"
    ok "listening on $HTTP_LISTEN"

    step "4/5 Point the Mac's system proxy at it"
    if ./sysproxy.sh check 2>/dev/null; then
      ok "already pointing at $HTTP_LISTEN (no password needed)"
    elif ./sysproxy.sh on 2>&1 | sed 's/^/  /'; then :
    else
      warn "system proxy not set. The proxy is still running; point apps at it manually:"
      echo "     shell:   export HTTPS_PROXY=http://$HTTP_LISTEN HTTP_PROXY=http://$HTTP_LISTEN"
      echo "     Chrome:  open -a 'Google Chrome' --args --proxy-server=http://$HTTP_LISTEN"
      echo "     Firefox: Settings > Network > Automatic proxy URL: http://$HTTP_LISTEN/proxy.pac"
    fi

    step "5/5 Verify"
    run_test
    echo
    echo "Done. Keep GlobalProtect connected. To undo everything: ./setup.sh uninstall"
    ;;

  uninstall)
    step "1/3 Restore the Mac's system proxy settings"
    ./sysproxy.sh off 2>&1 | sed 's/^/  /' || warn "could not change system proxy (not admin, or already off)"
    step "2/3 Remove login item and stop the proxy"
    ./install-launchd.sh uninstall >/dev/null && ok "removed $LABEL" || warn "LaunchAgent was not installed"
    pkill -f "splitproxy.py" 2>/dev/null && ok "stopped running proxy" || true
    step "3/3 Nothing else was changed"
    echo "  Routes, DNS and GlobalProtect were never modified."
    echo "  If you added HTTP(S)_PROXY exports to your shell rc or a ProxyCommand to ~/.ssh/config, remove those by hand."
    echo "  ~/.splitproxy (runtime copy + logs) has been removed. Delete this folder to remove the code:  rm -rf $HERE"
    ;;

  status)
    step "splitproxy status"
    [ -f "$PLIST" ] && ok "login item installed" || warn "login item not installed"
    if proxy_up; then ok "proxy answering on $HTTP_LISTEN"; curl -s "http://$HTTP_LISTEN/status" | sed 's/^/    /'
    else warn "proxy not running"; fi
    ./sysproxy.sh status | sed 's/^/  /'
    ;;

  test) run_test ;;

  *) sed -n '2,6p' "$0"; exit 1 ;;
esac
