#!/usr/bin/env bash
# infra/generate-selfsigned-cert.sh — generate a self-signed TLS certificate
# for a bare-IP deployment (see docs/runbooks/DEPLOYMENT.md, "No domain yet?").
#
# Caddy's automatic HTTPS (including its internal-CA on-demand issuance) is
# keyed by SNI. Real clients (browsers, curl, standard TLS libraries) never
# send SNI when connecting to a literal IP address (RFC 6066), so there is
# no SNI for Caddy to issue against. A statically generated cert with the IP
# as a SAN, loaded via Caddy's "tls <cert> <key>" directive, sidesteps that
# entirely: no SNI is needed because the certificate is not selected by SNI.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: infra/generate-selfsigned-cert.sh <VPS_IP> [output-dir]

Writes <output-dir>/selfsigned.crt and selfsigned.key (default output-dir:
infra/certs, already git-ignored and bind-mounted into the caddy service by
infra/docker-compose.prod.yml). Valid 825 days. Re-run to rotate.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi
if [[ $# -lt 1 ]]; then
  usage >&2
  exit 2
fi

ip="$1"
out_dir="${2:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/certs}"
mkdir -p "$out_dir"

openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout "$out_dir/selfsigned.key" -out "$out_dir/selfsigned.crt" \
  -days 825 -subj "/CN=$ip" -addext "subjectAltName=IP:$ip"

chmod 600 "$out_dir/selfsigned.key"
echo "Wrote $out_dir/selfsigned.crt and selfsigned.key for IP $ip"
