#include <unity.h>

#include <stdint.h>
#include <vector>

#include "BluettiEncryption.h"

void test_kex_checksum_is_big_endian_sum_of_body_bytes() {
  const uint8_t body[] = {0x02, 0x04, 0xa7, 0x9e, 0xf4, 0xcb};
  const uint16_t checksum = bluetti_kex_checksum(body, sizeof(body));

  TEST_ASSERT_EQUAL_HEX16(0x030a, checksum);
}

void test_xor_bytes_rejects_different_lengths() {
  const std::vector<uint8_t> a = {0x01, 0x02, 0x03};
  const std::vector<uint8_t> b = {0x04, 0x05};
  std::vector<uint8_t> out;

  TEST_ASSERT_FALSE(bluetti_xor_bytes(a, b, out));
}

void test_xor_bytes_returns_bytewise_xor() {
  const std::vector<uint8_t> a = {0x45, 0x9f, 0xc5, 0x35};
  const std::vector<uint8_t> b = {0xff, 0x00, 0x0f, 0xf0};
  std::vector<uint8_t> out;

  TEST_ASSERT_TRUE(bluetti_xor_bytes(a, b, out));
  TEST_ASSERT_EQUAL_UINT8(0xba, out[0]);
  TEST_ASSERT_EQUAL_UINT8(0x9f, out[1]);
  TEST_ASSERT_EQUAL_UINT8(0xca, out[2]);
  TEST_ASSERT_EQUAL_UINT8(0xc5, out[3]);
}

void test_secure_aes_frame_length_uses_big_endian_len_seed_and_block_padding() {
  const size_t plain_len = 8;

  TEST_ASSERT_EQUAL_UINT16(0x0008, bluetti_frame_plain_length_header(plain_len));
  TEST_ASSERT_EQUAL_UINT(22, bluetti_encrypted_frame_size(plain_len, true));
  TEST_ASSERT_EQUAL_UINT(18, bluetti_encrypted_frame_size(plain_len, false));
}

void test_modbus_crc_matches_bluetti_read_request() {
  const uint8_t request[] = {0x01, 0x03, 0x00, 0x0a, 0x00, 0x28};

  TEST_ASSERT_EQUAL_HEX16(0xd665, bluetti_modbus_crc(request, sizeof(request)));
}

int main(int argc, char **argv) {
  UNITY_BEGIN();
  RUN_TEST(test_kex_checksum_is_big_endian_sum_of_body_bytes);
  RUN_TEST(test_xor_bytes_rejects_different_lengths);
  RUN_TEST(test_xor_bytes_returns_bytewise_xor);
  RUN_TEST(test_secure_aes_frame_length_uses_big_endian_len_seed_and_block_padding);
  RUN_TEST(test_modbus_crc_matches_bluetti_read_request);
  return UNITY_END();
}
