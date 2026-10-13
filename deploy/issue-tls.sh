#!/bin/sh
set -eu
cd /opt/sentinela-sast
docker compose up -d api worker postgres redis codex proxy

# tls-init creates a one-day self-signed certificate only to let Nginx start.
# Once Certbot has a renewal configuration, preserve it and use the normal
# renewal path so rerunning this installer never deletes a valid certificate.
if docker compose --profile maintenance run --rm --entrypoint sh certbot \
  -c 'test -s /etc/letsencrypt/renewal/3.149.250.106.conf'; then
  docker compose --profile maintenance run --rm certbot renew \
    --cert-name 3.149.250.106 --preferred-profile shortlived \
    --no-random-sleep-on-renew
else
  docker compose --profile maintenance run --rm --entrypoint sh certbot \
    -c 'rm -rf /etc/letsencrypt/live/3.149.250.106 /etc/letsencrypt/archive/3.149.250.106'
  docker compose --profile maintenance run --rm certbot certonly \
    --non-interactive --agree-tos --register-unsafely-without-email \
    --preferred-profile shortlived --webroot --webroot-path /var/www/certbot \
    --ip-address 3.149.250.106 --cert-name 3.149.250.106
fi

docker compose exec -T proxy nginx -t
docker compose exec -T proxy nginx -s reload
python3 - <<'PY'
import json
from urllib.request import urlopen

with urlopen("https://3.149.250.106/health", timeout=15) as response:
    body = json.load(response)
    if response.status != 200 or body != {"status": "ok"}:
        raise SystemExit(f"HTTPS health check failed: {response.status} {body!r}")
print('HTTPS health check: {"status":"ok"}')
PY
