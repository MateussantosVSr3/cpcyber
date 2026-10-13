#!/bin/sh
set -eu
cd /opt/sentinela-sast
docker compose --profile maintenance run --rm certbot renew --quiet \
  --preferred-profile shortlived --no-random-sleep-on-renew
docker compose exec -T proxy nginx -t
docker compose exec -T proxy nginx -s reload
