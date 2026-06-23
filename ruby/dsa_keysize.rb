require 'openssl'

# OpenSSL::PKey::DSA.new(bits) — exercises Ruby DSA key-size capture.
# EXPECTED: DSA | - | 2048 | high | quantum-vulnerable
key = OpenSSL::PKey::DSA.new(2048)
