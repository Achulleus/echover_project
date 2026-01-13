set -euo pipefail

# Generate a self-signed TLS certificate for the Echover server.

mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout certs/server.key \
  -out certs/server.crt \
  -days 3650 \
  -subj "/C=AT/O=Echover Demo/CN=localhost"

echo "Generated certs/server.crt and certs/server.key"
