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
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
echo "installed $LABEL (runtime: $RUNTIME, log: $RUNTIME/logs/splitproxy.log)"
