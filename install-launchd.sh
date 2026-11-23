#!/bin/bash
# Run splitproxy at login and keep it alive. usage: ./install-launchd.sh [uninstall]
#
# macOS blocks launchd jobs from running out of ~/Desktop, ~/Documents and
# ~/Downloads (privacy protection; the job dies with exit 78 EX_CONFIG).
# So the runtime copy lives in ~/.splitproxy and launchd runs that. Re-run
# this script after editing .env to copy the new config and restart.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
LABEL=com.local.splitproxy
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
RUNTIME="$HOME/.splitproxy"
PY="$(command -v python3)"

if [ "${1:-}" = uninstall ]; then
  launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
  rm -f "$PLIST"
  rm -rf "$RUNTIME"
  echo "removed $LABEL and $RUNTIME"; exit 0
fi

[ -f "$HERE/.env" ] || cp "$HERE/.env.example" "$HERE/.env"
mkdir -p "$HOME/Library/LaunchAgents" "$RUNTIME/logs"
cp "$HERE/splitproxy.py" "$HERE/.env" "$RUNTIME/"

cat > "$PLIST" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array><string>$PY</string><string>$RUNTIME/splitproxy.py</string></array>
  <key>WorkingDirectory</key><string>$RUNTIME</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$RUNTIME/logs/splitproxy.log</string>
  <key>StandardErrorPath</key><string>$RUNTIME/logs/splitproxy.log</string>
</dict></plist>
PL
# bootout returns before the job is fully gone; bootstrapping too early fails
# with "Bootstrap failed: 5: Input/output error". Wait for it to disappear.
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
for _ in $(seq 1 50); do
  launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1 || break
  sleep 0.2
done
if ! launchctl bootstrap "gui/$(id -u)" "$PLIST" 2>/dev/null; then
  # Still loaded: restart it in place so it re-reads the copied .env.
  launchctl kickstart -k "gui/$(id -u)/$LABEL"
fi
echo "installed $LABEL (runtime: $RUNTIME, log: $RUNTIME/logs/splitproxy.log)"
