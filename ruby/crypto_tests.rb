require 'openssl'
require 'digest'
require 'bcrypt'

# EXPECTED: AES | GCM | 256 | info | quantum-safe
def encrypt_aes_gcm(key, plaintext)
  cipher = OpenSSL::Cipher.new('aes-256-gcm')
  cipher.encrypt
  cipher.key = key
  iv = cipher.random_iv
  cipher.auth_data = ''
  encrypted = cipher.update(plaintext) + cipher.final
  tag = cipher.auth_tag
  [encrypted, iv, tag]
end

# EXPECTED: AES | CBC | 256 | low | quantum-safe
def encrypt_aes_cbc(key, plaintext)
  cipher = OpenSSL::Cipher.new('aes-256-cbc')
  cipher.encrypt
  cipher.key = key
  iv = cipher.random_iv
  cipher.update(plaintext) + cipher.final
end

# EXPECTED: AES | ECB | 256 | high | quantum-safe
def encrypt_aes_ecb(key, plaintext)
  cipher = OpenSSL::Cipher.new('aes-256-ecb') # BAD: ECB mode
  cipher.encrypt
  cipher.key = key
  cipher.update(plaintext) + cipher.final
end

# EXPECTED: DES | ECB | 56 | critical | broken
def encrypt_des(key, plaintext)
  cipher = OpenSSL::Cipher.new('des-ecb') # BAD: broken cipher
  cipher.encrypt
  cipher.key = key
  cipher.update(plaintext) + cipher.final
end

# EXPECTED: RC4 | - | - | critical | broken
def encrypt_rc4(key, plaintext)
  cipher = OpenSSL::Cipher.new('rc4') # BAD
  cipher.encrypt
  cipher.key = key
  cipher.update(plaintext) + cipher.final
end

# EXPECTED: SHA-256 | - | - | info | quantum-safe
def hash_sha256(data)
  OpenSSL::Digest.new('SHA256').digest(data)
end

# EXPECTED: SHA-512 | - | - | info | quantum-safe
def hash_sha512(data)
  OpenSSL::Digest.new('SHA512').digest(data)
end

# EXPECTED: MD5 | - | - | high | broken
def hash_md5(data)
  OpenSSL::Digest.new('MD5').digest(data) # BAD
end

# EXPECTED: SHA-1 | - | - | medium | quantum-vulnerable
def hash_sha1(data)
  Digest::SHA1.hexdigest(data) # DEPRECATED
end

# EXPECTED: SHA-256 | - | - | info | quantum-safe
def hash_sha256_digest(data)
  Digest::SHA256.hexdigest(data)
end

# EXPECTED: MD5 | - | - | high | broken
def hash_md5_digest(data)
  Digest::MD5.hexdigest(data) # BAD
end

# EXPECTED: RSA | - | 2048 | medium | quantum-vulnerable
def generate_rsa_2048
  OpenSSL::PKey::RSA.generate(2048)
end

# EXPECTED: RSA | - | 4096 | low | quantum-vulnerable
def generate_rsa_4096
  OpenSSL::PKey::RSA.generate(4096)
end

# EXPECTED: ECDSA | - | 256 | low | quantum-vulnerable
def generate_ec_p256
  OpenSSL::PKey::EC.generate('prime256v1')
end

# EXPECTED: bcrypt | - | - | info | quantum-safe
def hash_password_bcrypt(password)
  BCrypt::Password.create(password)
end

# EXPECTED: HMAC-SHA256 | - | - | info | quantum-safe
def compute_hmac(key, data)
  OpenSSL::HMAC.hexdigest('SHA256', key, data)
end
