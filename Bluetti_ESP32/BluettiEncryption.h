#ifndef BLUETTI_ENCRYPTION_H
#define BLUETTI_ENCRYPTION_H

#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

uint16_t bluetti_kex_checksum(const uint8_t* data, size_t length);
bool bluetti_xor_bytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b, std::vector<uint8_t>& out);
uint16_t bluetti_frame_plain_length_header(size_t plain_len);
size_t bluetti_encrypted_frame_size(size_t plain_len, bool includes_seed);
uint16_t bluetti_modbus_crc(const uint8_t* data, size_t length);
std::string bluetti_hex(const uint8_t* data, size_t length, size_t max_length = 96);

class BluettiEncryption {
public:
  enum State {
    WAITING_CHALLENGE,
    TEMP_KEY_READY,
    PEER_KEY_VERIFIED,
    SECURE_KEY_READY,
    FAILED
  };

  BluettiEncryption();

  void reset();
  bool isReadyForCommands() const;
  State state() const;
  const char* stateName() const;
  const char* lastError() const;

  bool processIncoming(
      const uint8_t* data,
      size_t length,
      std::vector<uint8_t>& write_response,
      std::vector<uint8_t>& plaintext_response);

  bool encryptCommand(const uint8_t* data, size_t length, std::vector<uint8_t>& encrypted);

private:
  State state_;
  std::string last_error_;
  std::vector<uint8_t> unsecure_aes_key_;
  std::vector<uint8_t> unsecure_aes_iv_;
  std::vector<uint8_t> secure_aes_key_;
  std::vector<uint8_t> peer_pubkey_;
  std::vector<uint8_t> my_pubkey_;
  std::vector<uint8_t> my_private_key_;
  std::vector<uint8_t> peer_pubkey_response_;

  void setState(State next);
  void setError(const char* error);
  bool isPreKeyExchange(const uint8_t* data, size_t length) const;
  bool verifyKexChecksum(const uint8_t* data, size_t length) const;
  bool handleKexMessage(
      const uint8_t* data,
      size_t length,
      std::vector<uint8_t>& write_response,
      std::vector<uint8_t>& plaintext_response);
  bool buildKexMessage(const std::vector<uint8_t>& body, std::vector<uint8_t>& out) const;
  bool deriveTemporaryKey(const uint8_t* challenge, size_t length);
  bool aesDecrypt(const uint8_t* data, size_t length, const std::vector<uint8_t>& key, const uint8_t* fixed_iv, std::vector<uint8_t>& out);
  bool aesEncrypt(const uint8_t* data, size_t length, const std::vector<uint8_t>& key, const uint8_t* fixed_iv, std::vector<uint8_t>& out);
  bool verifyPeerKeyAndBuildResponse(const uint8_t* data, size_t length, std::vector<uint8_t>& write_response);
  bool calculateSecureKey(const uint8_t* data, size_t length);
};

#endif
