#!/bin/sh
set -eu
cd /opt/sentinela-sast
chmod 700 deploy/issue-tls.sh deploy/renew-tls.sh
docker compose build api worker codex
./deploy/issue-tls.sh
sudo install -m 0644 deploy/sentinela-tls-renew.service /etc/systemd/system/sentinela-tls-renew.service
sudo install -m 0644 deploy/sentinela-tls-renew.timer /etc/systemd/system/sentinela-tls-renew.timer
sudo systemctl daemon-reload
sudo systemctl enable --now sentinela-tls-renew.timer
sudo systemctl list-timers sentinela-tls-renew.timer --no-pager
