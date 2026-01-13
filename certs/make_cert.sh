set -euo pipefail

# Generates certs/server.crt and certs/server.key (self-signed) for local testing.

CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRT="$CERT_DIR/server.crt"
KEY="$CERT_DIR/server.key"

TMP_CFG="$(mktemp)"
trap 'rm -f "$TMP_CFG"' EXIT

cat > "$TMP_CFG" <<'EOF'
[req]
prompt = no
distinguished_name = dn
x509_extensions = v3_req

[dn]
C = AT
O = Echover Demo
CN = localhost

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout "$KEY" -out "$CRT" -config "$TMP_CFG" -extensions v3_req

echo "Wrote: $CRT"
echo "Wrote: $KEY"
