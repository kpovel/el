#!/usr/bin/env bash
set -euo pipefail

REMOTE="pi@pi.local"
REMOTE_DIR="/home/pi/ecoflow-grid-monitor"
BINARY="ecoflow-grid-monitor"
SERVICE_NAME="ecoflow-grid-monitor"

SOCK=$(mktemp -u /tmp/deploy-ssh-XXXXXX)
SSH_OPTS="-o ControlMaster=auto -o ControlPath=$SOCK -o ControlPersist=60"

cleanup() { ssh -o ControlPath="$SOCK" -O exit "$REMOTE" 2>/dev/null || true; }
trap cleanup EXIT

echo "==> Authenticating"
ssh $SSH_OPTS -fN "$REMOTE"

echo "==> Building single binary for linux-arm64"
bun build src/server.ts --compile --target=bun-linux-arm64 --external x11 --external debug --outfile "build/$BINARY"

echo "==> Stopping service"
ssh $SSH_OPTS "$REMOTE" "sudo systemctl stop $SERVICE_NAME 2>/dev/null || true"

echo "==> Copying binary and service file"
ssh $SSH_OPTS "$REMOTE" "mkdir -p $REMOTE_DIR"
scp -o ControlPath="$SOCK" "build/$BINARY" "$REMOTE:$REMOTE_DIR/$BINARY"
scp -o ControlPath="$SOCK" "$SERVICE_NAME.service" "$REMOTE:$REMOTE_DIR/$SERVICE_NAME.service"

echo "==> Installing systemd service"
ssh $SSH_OPTS "$REMOTE" "sudo cp $REMOTE_DIR/$SERVICE_NAME.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable $SERVICE_NAME"

echo "==> Restarting service"
ssh $SSH_OPTS "$REMOTE" "sudo systemctl restart $SERVICE_NAME"

echo "==> Done. Checking status:"
ssh $SSH_OPTS "$REMOTE" "sudo systemctl status $SERVICE_NAME --no-pager" || true
