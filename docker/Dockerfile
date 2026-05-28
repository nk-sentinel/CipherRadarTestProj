# Dockerfile crypto benchmark fixture for CipherRadar recall measurement.
# Scanner models: unpinned `apt/apt-get install ... openssl` (RUN), EXPOSE 443.

FROM debian:bookworm-slim

# --- Unpinned openssl install via apt-get (modelled) ---
# EXPECTED: Unpinned OpenSSL install | | | medium | quantum-vulnerable
RUN apt-get update && apt-get install -y openssl ca-certificates

# --- Unpinned openssl install via apk (Alpine) — docs imply container crypto coverage ---
# EXPECTED: Unpinned OpenSSL install | | | medium | quantum-vulnerable
RUN apk add --no-cache openssl

# --- libssl-dev install (TLS library) — crypto-relevant package ---
# EXPECTED: Unpinned crypto library install | | | medium | quantum-vulnerable
RUN apt-get install -y libssl-dev

# --- TLS endpoint: EXPOSE 443 (modelled) ---
# EXPECTED: TLS endpoint: EXPOSE 443 | tls | | info | quantum-vulnerable
EXPOSE 443

# --- TLS endpoint on alternate port — docs imply TLS endpoint detection ---
# EXPECTED: TLS endpoint: EXPOSE 8443 | tls | | info | quantum-vulnerable
EXPOSE 8443/tcp

CMD ["/usr/bin/myserver"]
