#!/usr/bin/env bash
# Thinkpad6g.net Launcher

APP_DIR="/home/max/airtel-wifi-manager"
PORT=8765
URL="http://127.0.0.1:${PORT}"

export DISPLAY="${DISPLAY:-:0.0}"

# 1. Start server if not already running
if ! curl -s -m 1 "${URL}/api/live" > /dev/null 2>&1; then
    echo "Starting Thinkpad6g.net service..."
    systemctl --user start airtel-wifi-manager.service 2>/dev/null || nohup python3 "${APP_DIR}/app.py" > "${APP_DIR}/server.log" 2>&1 &
    
    # Wait for server to become responsive (up to 10 seconds)
    for i in {1..20}; do
        if curl -s -m 1 "${URL}/api/live" > /dev/null 2>&1; then
            echo "Server ready!"
            break
        fi
        sleep 0.5
    done
fi

# 2. Open dashboard in standalone app window if chrome/chromium is available
if which google-chrome > /dev/null 2>&1; then
    google-chrome --app="${URL}" > /dev/null 2>&1 &
elif which chromium > /dev/null 2>&1; then
    chromium --app="${URL}" > /dev/null 2>&1 &
elif which xdg-open > /dev/null 2>&1; then
    xdg-open "${URL}" > /dev/null 2>&1 &
else
    firefox "${URL}" > /dev/null 2>&1 &
fi
