#!/usr/bin/env bash
# 生成验收测试用的自签 CA 与服务端证书对 (10 年).
# 手动执行, 不进任何自动流程. 产物: ca.pem / server.pem / server.key (提交),
# ca.key 仅本地保留供再次签发, 不提交.
set -euo pipefail
cd "$(dirname "$0")"

DAYS=3650

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout ca.key -out ca.pem -days "$DAYS" \
  -subj "/CN=cfdoh-acceptance-test CA"

openssl req -newkey rsa:2048 -nodes \
  -keyout server.key -out server.csr \
  -subj "/CN=localhost"

cat > server.ext <<'EOF'
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF
openssl x509 -req -in server.csr \
  -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.pem -days "$DAYS" -extfile server.ext

rm -f server.csr server.ext ca.srl
echo "certs written: ca.pem server.pem server.key"
