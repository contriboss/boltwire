#!/bin/sh
# TLS test sidecar: self-signed cert + stunnel terminating TLS on :17689,
# forwarding plain Bolt to podman container.
# Use container from activecyper gem as example.
# Too lazy to copy them over here.
#
#   tls-sidecar.sh up
#   tls-sidecar.sh down
set -eu

NAME=boltwire-tls-sidecar
NET=activecypher_default
PORT=17689
MTLS_PORT=17691
DIR="${TMPDIR:-/tmp}/boltwire-tls"

up() {
    mkdir -p "$DIR"
    # CA:FALSE: openssl 3 defaults to CA:TRUE, which webpki rejects as an
    # end-entity cert (CaUsedAsEndEntity).
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
        -keyout "$DIR/key.pem" -out "$DIR/cert.pem" \
        -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" \
        -addext "basicConstraints=critical,CA:FALSE" \
        2>/dev/null

    # client identity for the mTLS listener
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
        -keyout "$DIR/client-key.pem" -out "$DIR/client-cert.pem" \
        -subj "/CN=boltwire-client" \
        -addext "basicConstraints=critical,CA:FALSE" \
        2>/dev/null

    cat > "$DIR/stunnel.conf" <<EOF
foreground = yes
[bolt]
accept = 0.0.0.0:$PORT
connect = memgraph:7687
cert = /tls/cert.pem
key = /tls/key.pem

[bolt-mtls]
accept = 0.0.0.0:$MTLS_PORT
connect = memgraph:7687
cert = /tls/cert.pem
key = /tls/key.pem
verifyPeer = yes
CAfile = /tls/client-cert.pem
EOF

    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker run -d --name "$NAME" --network "$NET" -p "$PORT:$PORT" -p "$MTLS_PORT:$MTLS_PORT" \
        -v "$DIR:/tls:ro" alpine:3 \
        sh -c "apk add --no-cache stunnel >/dev/null && exec stunnel /tls/stunnel.conf" >/dev/null

    # docker-proxy binds the host port before stunnel is up inside; probe with
    # an actual TLS handshake, not a TCP connect.
    i=0
    until openssl s_client -connect "127.0.0.1:$PORT" -verify_quiet </dev/null >/dev/null 2>&1; do
        i=$((i + 1))
        [ "$i" -gt 60 ] && { echo "sidecar failed to start" >&2; docker logs "$NAME" >&2; exit 1; }
        sleep 0.5
    done

    echo "export BOLT_TLS_ADDR=127.0.0.1:$PORT"
    echo "export BOLT_TLS_SERVERNAME=localhost"
    echo "export BOLT_TLS_CA=$DIR/cert.pem"
    echo "export BOLT_MTLS_ADDR=127.0.0.1:$MTLS_PORT"
    echo "export BOLT_TLS_CLIENT_CERT=$DIR/client-cert.pem"
    echo "export BOLT_TLS_CLIENT_KEY=$DIR/client-key.pem"
}

down() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    rm -rf "$DIR"
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    *) echo "usage: $0 up|down" >&2; exit 1 ;;
esac
