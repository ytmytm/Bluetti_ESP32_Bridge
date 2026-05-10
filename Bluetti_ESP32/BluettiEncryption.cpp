#include "BluettiEncryption.h"

#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <stdio.h>

#if defined(ARDUINO_ARCH_ESP32) || defined(ESP32)
#include <esp_system.h>
#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/md5.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#define BLUETTI_ESP32_CRYPTO 1
#else
#define BLUETTI_ESP32_CRYPTO 0
#endif

namespace {

const uint8_t KEX_MAGIC[] = {0x2a, 0x2a};
const size_t AES_BLOCK_SIZE_BYTES = 16;

const char* LOCAL_AES_KEY_HEX = "459FC535808941F17091E0993EE3E93D";
const char* PRIVATE_KEY_L1_HEX = "4F19A16E3E87BDD9BD24D3E5495B88041511943CBC8B969ADE9641D0F56AF337";
const char* PUBLIC_KEY_K2_HEX =
    "3059301306072a8648ce3d020106082a8648ce3d03010703420004"
    "A73ABF5D2232C8C1C72E68304343C272495E3A8FD6F30EA96DE2F4B3CE60B251"
    "EE21AC667CF8A71E18B46B664EAEFFE3C489F24F695B6411DB7E22CCC85A8594";

bool hexToBytes(const char* hex, std::vector<uint8_t>& out) {
  out.clear();
  for (size_t i = 0; hex[i] != '\0'; i += 2) {
    if (hex[i + 1] == '\0') {
      return false;
    }
    char byte_str[3] = {hex[i], hex[i + 1], '\0'};
    out.push_back(static_cast<uint8_t>(strtoul(byte_str, nullptr, 16)));
  }
  return true;
}

void appendUint16BE(std::vector<uint8_t>& out, uint16_t value) {
  out.push_back(static_cast<uint8_t>(value >> 8));
  out.push_back(static_cast<uint8_t>(value & 0xff));
}

void md5Bytes(const uint8_t* data, size_t length, std::vector<uint8_t>& out) {
  out.assign(16, 0);
#if BLUETTI_ESP32_CRYPTO
  mbedtls_md5_ret(data, length, out.data());
#else
  (void)data;
  (void)length;
#endif
}

#if BLUETTI_ESP32_CRYPTO
bool seedRng(mbedtls_entropy_context& entropy, mbedtls_ctr_drbg_context& ctr_drbg) {
  const char* personal = "bluetti-esp32";
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  return mbedtls_ctr_drbg_seed(
             &ctr_drbg,
             mbedtls_entropy_func,
             &entropy,
             reinterpret_cast<const unsigned char*>(personal),
             strlen(personal)) == 0;
}

bool rawEcdsaToDer(const uint8_t* raw, size_t raw_len, std::vector<uint8_t>& der) {
  if (raw_len != 64) {
    return false;
  }

  auto appendInt = [](std::vector<uint8_t>& out, const uint8_t* value) {
    size_t start = 0;
    while (start < 31 && value[start] == 0x00 && (value[start + 1] & 0x80) == 0) {
      start++;
    }

    const bool needs_zero = (value[start] & 0x80) != 0;
    const uint8_t len = static_cast<uint8_t>((32 - start) + (needs_zero ? 1 : 0));
    out.push_back(0x02);
    out.push_back(len);
    if (needs_zero) {
      out.push_back(0x00);
    }
    out.insert(out.end(), value + start, value + 32);
  };

  std::vector<uint8_t> body;
  appendInt(body, raw);
  appendInt(body, raw + 32);

  der.clear();
  der.push_back(0x30);
  der.push_back(static_cast<uint8_t>(body.size()));
  der.insert(der.end(), body.begin(), body.end());
  return true;
}

bool derEcdsaToRaw(const uint8_t* der, size_t der_len, std::vector<uint8_t>& raw) {
  if (der_len < 8 || der[0] != 0x30) {
    return false;
  }

  size_t index = 2;
  raw.assign(64, 0);
  for (int part = 0; part < 2; part++) {
    if (index + 2 > der_len || der[index++] != 0x02) {
      return false;
    }
    size_t len = der[index++];
    if (index + len > der_len) {
      return false;
    }
    const uint8_t* value = der + index;
    if (len > 32 && value[0] == 0x00) {
      value++;
      len--;
    }
    if (len > 32) {
      return false;
    }
    memcpy(raw.data() + (part * 32) + (32 - len), value, len);
    index += der[index - 1];
  }
  return true;
}

bool sha256Bytes(const uint8_t* data, size_t length, uint8_t out[32]) {
  return mbedtls_sha256_ret(data, length, out, 0) == 0;
}
#endif

}  // namespace

uint16_t bluetti_kex_checksum(const uint8_t* data, size_t length) {
  uint32_t checksum = 0;
  for (size_t i = 0; i < length; i++) {
    checksum += data[i];
  }
  return static_cast<uint16_t>(checksum & 0xffff);
}

bool bluetti_xor_bytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b, std::vector<uint8_t>& out) {
  if (a.size() != b.size()) {
    out.clear();
    return false;
  }

  out.resize(a.size());
  for (size_t i = 0; i < a.size(); i++) {
    out[i] = a[i] ^ b[i];
  }
  return true;
}

uint16_t bluetti_frame_plain_length_header(size_t plain_len) {
  return static_cast<uint16_t>(plain_len & 0xffff);
}

size_t bluetti_encrypted_frame_size(size_t plain_len, bool includes_seed) {
  const size_t padded = ((plain_len + AES_BLOCK_SIZE_BYTES - 1) / AES_BLOCK_SIZE_BYTES) * AES_BLOCK_SIZE_BYTES;
  return 2 + (includes_seed ? 4 : 0) + padded;
}

uint16_t bluetti_modbus_crc(const uint8_t* data, size_t length) {
  uint16_t crc = 0xffff;
  for (size_t i = 0; i < length; i++) {
    crc ^= data[i];
    for (int bit = 0; bit < 8; bit++) {
      if ((crc & 0x0001) != 0) {
        crc = (crc >> 1) ^ 0xa001;
      } else {
        crc >>= 1;
      }
    }
  }
  return crc;
}

std::string bluetti_hex(const uint8_t* data, size_t length, size_t max_length) {
  std::string out;
  const size_t printable = std::min(length, max_length);
  char buf[4];
  for (size_t i = 0; i < printable; i++) {
    snprintf(buf, sizeof(buf), "%02x", data[i]);
    out += buf;
    if ((i + 1) % 2 == 0 && i + 1 < printable) {
      out += ' ';
    }
  }
  if (printable < length) {
    out += " ...";
  }
  return out;
}

BluettiEncryption::BluettiEncryption() {
  reset();
}

void BluettiEncryption::reset() {
  state_ = WAITING_CHALLENGE;
  last_error_.clear();
  unsecure_aes_key_.clear();
  unsecure_aes_iv_.clear();
  secure_aes_key_.clear();
  peer_pubkey_.clear();
  my_pubkey_.clear();
  my_private_key_.clear();
  peer_pubkey_response_.clear();
}

bool BluettiEncryption::isReadyForCommands() const {
  return state_ == SECURE_KEY_READY && secure_aes_key_.size() == 32;
}

BluettiEncryption::State BluettiEncryption::state() const {
  return state_;
}

const char* BluettiEncryption::stateName() const {
  switch (state_) {
    case WAITING_CHALLENGE:
      return "waiting_challenge";
    case TEMP_KEY_READY:
      return "temp_key_ready";
    case PEER_KEY_VERIFIED:
      return "peer_key_verified";
    case SECURE_KEY_READY:
      return "secure_key_ready";
    case FAILED:
      return "failed";
  }
  return "unknown";
}

const char* BluettiEncryption::lastError() const {
  return last_error_.c_str();
}

void BluettiEncryption::setState(State next) {
  state_ = next;
}

void BluettiEncryption::setError(const char* error) {
  last_error_ = error;
  state_ = FAILED;
}

bool BluettiEncryption::isPreKeyExchange(const uint8_t* data, size_t length) const {
  return length >= 4 && data[0] == KEX_MAGIC[0] && data[1] == KEX_MAGIC[1];
}

bool BluettiEncryption::verifyKexChecksum(const uint8_t* data, size_t length) const {
  if (!isPreKeyExchange(data, length)) {
    return false;
  }
  const size_t body_len = length - 4;
  const uint16_t expected = (static_cast<uint16_t>(data[length - 2]) << 8) | data[length - 1];
  return bluetti_kex_checksum(data + 2, body_len) == expected;
}

bool BluettiEncryption::buildKexMessage(const std::vector<uint8_t>& body, std::vector<uint8_t>& out) const {
  out.clear();
  out.push_back(KEX_MAGIC[0]);
  out.push_back(KEX_MAGIC[1]);
  out.insert(out.end(), body.begin(), body.end());
  appendUint16BE(out, bluetti_kex_checksum(body.data(), body.size()));
  return true;
}

bool BluettiEncryption::deriveTemporaryKey(const uint8_t* challenge, size_t length) {
  if (length != 4) {
    setError("challenge length is not 4 bytes");
    return false;
  }

  uint8_t reversed[4] = {challenge[3], challenge[2], challenge[1], challenge[0]};
  md5Bytes(reversed, sizeof(reversed), unsecure_aes_iv_);

  std::vector<uint8_t> local_key;
  if (!hexToBytes(LOCAL_AES_KEY_HEX, local_key) || !bluetti_xor_bytes(unsecure_aes_iv_, local_key, unsecure_aes_key_)) {
    setError("failed to derive temporary key");
    return false;
  }

  setState(TEMP_KEY_READY);
  return true;
}

bool BluettiEncryption::processIncoming(
    const uint8_t* data,
    size_t length,
    std::vector<uint8_t>& write_response,
    std::vector<uint8_t>& plaintext_response) {
  write_response.clear();
  plaintext_response.clear();

  if (isPreKeyExchange(data, length)) {
    return handleKexMessage(data, length, write_response, plaintext_response);
  }

  if (unsecure_aes_key_.empty()) {
    setError("encrypted packet received before temporary key");
    return false;
  }

  std::vector<uint8_t> decrypted;
  const bool secure = !secure_aes_key_.empty();
  const std::vector<uint8_t>& key = secure ? secure_aes_key_ : unsecure_aes_key_;
  const uint8_t* fixed_iv = secure ? nullptr : unsecure_aes_iv_.data();
  if (!aesDecrypt(data, length, key, fixed_iv, decrypted)) {
    return false;
  }

  if (isPreKeyExchange(decrypted.data(), decrypted.size())) {
    return handleKexMessage(decrypted.data(), decrypted.size(), write_response, plaintext_response);
  }

  plaintext_response = decrypted;
  return true;
}

bool BluettiEncryption::handleKexMessage(
    const uint8_t* data,
    size_t length,
    std::vector<uint8_t>& write_response,
    std::vector<uint8_t>& plaintext_response) {
  plaintext_response.clear();
  if (!verifyKexChecksum(data, length)) {
    setError("key-exchange checksum mismatch");
    return false;
  }

  const uint8_t* body = data + 2;
  const size_t body_len = length - 4;
  if (body_len < 2) {
    setError("key-exchange body too short");
    return false;
  }

  const uint8_t type = body[0];
  const uint8_t* payload = body + 2;
  const size_t payload_len = body_len - 2;

  if (type == 0x01) {
    if (!deriveTemporaryKey(payload, payload_len)) {
      return false;
    }

    std::vector<uint8_t> response_body = {0x02, 0x04};
    response_body.insert(response_body.end(), unsecure_aes_iv_.begin() + 8, unsecure_aes_iv_.begin() + 12);
    return buildKexMessage(response_body, write_response);
  }

  if (type == 0x03) {
    return true;
  }

  if (type == 0x04) {
    return verifyPeerKeyAndBuildResponse(payload, payload_len, write_response);
  }

  if (type == 0x06) {
    return calculateSecureKey(payload, payload_len);
  }

  setError("unknown key-exchange message type");
  return false;
}

bool BluettiEncryption::aesDecrypt(const uint8_t* data, size_t length, const std::vector<uint8_t>& key, const uint8_t* fixed_iv, std::vector<uint8_t>& out) {
  out.clear();
  if (length < 2 || key.size() != 16 && key.size() != 32) {
    setError("invalid AES decrypt input");
    return false;
  }

  const size_t plain_len = (static_cast<size_t>(data[0]) << 8) | data[1];
  uint8_t iv[16];
  size_t encrypted_offset = 2;
  if (fixed_iv == nullptr) {
    if (length < 6) {
      setError("secure AES frame missing IV seed");
      return false;
    }
    std::vector<uint8_t> computed_iv;
    md5Bytes(data + 2, 4, computed_iv);
    memcpy(iv, computed_iv.data(), sizeof(iv));
    encrypted_offset = 6;
  } else {
    memcpy(iv, fixed_iv, sizeof(iv));
  }

  const size_t encrypted_len = length - encrypted_offset;
  if (encrypted_len % AES_BLOCK_SIZE_BYTES != 0 || plain_len > encrypted_len) {
    setError("invalid AES encrypted length");
    return false;
  }

#if BLUETTI_ESP32_CRYPTO
  out.assign(encrypted_len, 0);
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  int rc = mbedtls_aes_setkey_dec(&aes, key.data(), key.size() * 8);
  if (rc == 0) {
    rc = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, encrypted_len, iv, data + encrypted_offset, out.data());
  }
  mbedtls_aes_free(&aes);
  if (rc != 0) {
    setError("AES decrypt failed");
    return false;
  }
  out.resize(plain_len);
  return true;
#else
  (void)data;
  (void)iv;
  out.clear();
  setError("AES decrypt unavailable on native test target");
  return false;
#endif
}

bool BluettiEncryption::aesEncrypt(const uint8_t* data, size_t length, const std::vector<uint8_t>& key, const uint8_t* fixed_iv, std::vector<uint8_t>& out) {
  out.clear();
  if (key.size() != 16 && key.size() != 32) {
    setError("invalid AES encrypt key");
    return false;
  }

  appendUint16BE(out, static_cast<uint16_t>(length));
  uint8_t iv[16];
  if (fixed_iv == nullptr) {
#if BLUETTI_ESP32_CRYPTO
    const uint32_t seed = esp_random();
    const uint8_t seed_bytes[] = {
        static_cast<uint8_t>(seed >> 24),
        static_cast<uint8_t>(seed >> 16),
        static_cast<uint8_t>(seed >> 8),
        static_cast<uint8_t>(seed)};
    out.insert(out.end(), seed_bytes, seed_bytes + sizeof(seed_bytes));
    std::vector<uint8_t> computed_iv;
    md5Bytes(seed_bytes, sizeof(seed_bytes), computed_iv);
    memcpy(iv, computed_iv.data(), sizeof(iv));
#else
    setError("AES encrypt unavailable on native test target");
    return false;
#endif
  } else {
    memcpy(iv, fixed_iv, sizeof(iv));
  }

  std::vector<uint8_t> padded(data, data + length);
  padded.resize(((length + AES_BLOCK_SIZE_BYTES - 1) / AES_BLOCK_SIZE_BYTES) * AES_BLOCK_SIZE_BYTES, 0x00);
  const size_t encrypted_offset = out.size();
  out.resize(encrypted_offset + padded.size());

#if BLUETTI_ESP32_CRYPTO
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  int rc = mbedtls_aes_setkey_enc(&aes, key.data(), key.size() * 8);
  if (rc == 0) {
    rc = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded.size(), iv, padded.data(), out.data() + encrypted_offset);
  }
  mbedtls_aes_free(&aes);
  if (rc != 0) {
    setError("AES encrypt failed");
    return false;
  }
  return true;
#else
  setError("AES encrypt unavailable on native test target");
  return false;
#endif
}

bool BluettiEncryption::encryptCommand(const uint8_t* data, size_t length, std::vector<uint8_t>& encrypted) {
  if (!isReadyForCommands()) {
    setError("secure key not ready");
    return false;
  }
  return aesEncrypt(data, length, secure_aes_key_, nullptr, encrypted);
}

bool BluettiEncryption::verifyPeerKeyAndBuildResponse(const uint8_t* data, size_t length, std::vector<uint8_t>& write_response) {
  write_response.clear();
  if (length != 128 || unsecure_aes_iv_.size() != 16 || unsecure_aes_key_.size() != 16) {
    setError("invalid peer key message");
    return false;
  }

  if (!peer_pubkey_.empty() && peer_pubkey_.size() == 64 &&
      std::equal(peer_pubkey_.begin(), peer_pubkey_.end(), data) &&
      !peer_pubkey_response_.empty()) {
    write_response = peer_pubkey_response_;
    return true;
  }

#if BLUETTI_ESP32_CRYPTO
  std::vector<uint8_t> public_key_der;
  if (!hexToBytes(PUBLIC_KEY_K2_HEX, public_key_der)) {
    setError("invalid public key constant");
    return false;
  }

  std::vector<uint8_t> signed_data(data, data + 64);
  signed_data.insert(signed_data.end(), unsecure_aes_iv_.begin(), unsecure_aes_iv_.end());

  uint8_t hash[32];
  if (!sha256Bytes(signed_data.data(), signed_data.size(), hash)) {
    setError("SHA256 failed");
    return false;
  }

  std::vector<uint8_t> der_sig;
  if (!rawEcdsaToDer(data + 64, 64, der_sig)) {
    setError("peer signature DER conversion failed");
    return false;
  }

  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);
  int rc = mbedtls_pk_parse_public_key(&pk, public_key_der.data(), public_key_der.size());
  if (rc == 0) {
    rc = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 0, der_sig.data(), der_sig.size());
  }
  mbedtls_pk_free(&pk);
  if (rc != 0) {
    setError("peer public key signature verify failed");
    return false;
  }

  peer_pubkey_.assign(data, data + 64);

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  if (!seedRng(entropy, ctr_drbg)) {
    setError("RNG seed failed");
    return false;
  }

  mbedtls_ecp_group grp;
  mbedtls_mpi d;
  mbedtls_ecp_point q;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  mbedtls_ecp_point_init(&q);

  rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
  if (rc == 0) {
    rc = mbedtls_ecp_gen_keypair(&grp, &d, &q, mbedtls_ctr_drbg_random, &ctr_drbg);
  }

  my_private_key_.assign(32, 0);
  my_pubkey_.assign(64, 0);
  if (rc == 0) {
    rc = mbedtls_mpi_write_binary(&d, my_private_key_.data(), 32);
  }
  if (rc == 0) {
    rc = mbedtls_mpi_write_binary(&q.X, my_pubkey_.data(), 32);
  }
  if (rc == 0) {
    rc = mbedtls_mpi_write_binary(&q.Y, my_pubkey_.data() + 32, 32);
  }

  mbedtls_ecp_point_free(&q);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
  if (rc != 0) {
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    setError("local ECDH key generation failed");
    return false;
  }

  std::vector<uint8_t> signing_private;
  if (!hexToBytes(PRIVATE_KEY_L1_HEX, signing_private)) {
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    setError("invalid signing private key constant");
    return false;
  }

  std::vector<uint8_t> to_sign = my_pubkey_;
  to_sign.insert(to_sign.end(), unsecure_aes_iv_.begin(), unsecure_aes_iv_.end());
  if (!sha256Bytes(to_sign.data(), to_sign.size(), hash)) {
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    setError("signing hash failed");
    return false;
  }

  mbedtls_ecdsa_context sign_ctx;
  mbedtls_ecdsa_init(&sign_ctx);
  rc = mbedtls_ecp_group_load(&sign_ctx.grp, MBEDTLS_ECP_DP_SECP256R1);
  if (rc == 0) {
    rc = mbedtls_mpi_read_binary(&sign_ctx.d, signing_private.data(), signing_private.size());
  }
  if (rc == 0) {
    rc = mbedtls_ecp_mul(&sign_ctx.grp, &sign_ctx.Q, &sign_ctx.d, &sign_ctx.grp.G, mbedtls_ctr_drbg_random, &ctr_drbg);
  }

  uint8_t der_signature[80];
  size_t der_signature_len = 0;
  if (rc == 0) {
    rc = mbedtls_ecdsa_write_signature(
        &sign_ctx,
        MBEDTLS_MD_SHA256,
        hash,
        sizeof(hash),
        der_signature,
        &der_signature_len,
        mbedtls_ctr_drbg_random,
        &ctr_drbg);
  }
  mbedtls_ecdsa_free(&sign_ctx);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  if (rc != 0) {
    setError("local public key signing failed");
    return false;
  }

  std::vector<uint8_t> raw_signature;
  if (!derEcdsaToRaw(der_signature, der_signature_len, raw_signature)) {
    setError("local signature raw conversion failed");
    return false;
  }

  std::vector<uint8_t> body = {0x05, 0x80};
  body.insert(body.end(), my_pubkey_.begin(), my_pubkey_.end());
  body.insert(body.end(), raw_signature.begin(), raw_signature.end());

  std::vector<uint8_t> kex_message;
  buildKexMessage(body, kex_message);
  setState(PEER_KEY_VERIFIED);
  if (!aesEncrypt(kex_message.data(), kex_message.size(), unsecure_aes_key_, unsecure_aes_iv_.data(), write_response)) {
    return false;
  }
  peer_pubkey_response_ = write_response;
  return true;
#else
  (void)data;
  setError("ECDH/ECDSA unavailable on native test target");
  return false;
#endif
}

bool BluettiEncryption::calculateSecureKey(const uint8_t* data, size_t length) {
  if (length != 1 || data[0] != 0x00 || peer_pubkey_.size() != 64 || my_private_key_.size() != 32) {
    setError("invalid secure-key acceptance message");
    return false;
  }

#if BLUETTI_ESP32_CRYPTO
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  if (!seedRng(entropy, ctr_drbg)) {
    setError("RNG seed failed");
    return false;
  }

  mbedtls_ecp_group grp;
  mbedtls_ecp_point peer;
  mbedtls_mpi d;
  mbedtls_mpi z;
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&peer);
  mbedtls_mpi_init(&d);
  mbedtls_mpi_init(&z);

  int rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
  if (rc == 0) {
    rc = mbedtls_mpi_read_binary(&peer.X, peer_pubkey_.data(), 32);
  }
  if (rc == 0) {
    rc = mbedtls_mpi_read_binary(&peer.Y, peer_pubkey_.data() + 32, 32);
  }
  if (rc == 0) {
    rc = mbedtls_mpi_lset(&peer.Z, 1);
  }
  if (rc == 0) {
    rc = mbedtls_mpi_read_binary(&d, my_private_key_.data(), my_private_key_.size());
  }
  if (rc == 0) {
    rc = mbedtls_ecdh_compute_shared(&grp, &z, &peer, &d, mbedtls_ctr_drbg_random, &ctr_drbg);
  }

  secure_aes_key_.assign(32, 0);
  if (rc == 0) {
    rc = mbedtls_mpi_write_binary(&z, secure_aes_key_.data(), secure_aes_key_.size());
  }

  mbedtls_mpi_free(&z);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_point_free(&peer);
  mbedtls_ecp_group_free(&grp);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  if (rc != 0) {
    setError("ECDH shared secret failed");
    return false;
  }

  setState(SECURE_KEY_READY);
  return true;
#else
  setError("ECDH unavailable on native test target");
  return false;
#endif
}
