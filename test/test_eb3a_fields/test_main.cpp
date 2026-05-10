#include <unity.h>

#include "DeviceType.h"
#include "DEVICE_EB3A.h"

void test_eb3a_publishes_pack_voltage() {
  bool found = false;

  for (int i = 0; i < sizeof(bluetti_device_state) / sizeof(device_field_data_t); i++) {
    if (bluetti_device_state[i].f_name == PACK_VOLTAGE) {
      found = true;
      TEST_ASSERT_EQUAL_HEX8(0x00, bluetti_device_state[i].f_page);
      TEST_ASSERT_EQUAL_HEX8(0x62, bluetti_device_state[i].f_offset);
      TEST_ASSERT_EQUAL(1, bluetti_device_state[i].f_size);
      TEST_ASSERT_EQUAL(2, bluetti_device_state[i].f_scale);
      TEST_ASSERT_EQUAL(DECIMAL_FIELD, bluetti_device_state[i].f_type);
    }
  }

  TEST_ASSERT_TRUE(found);
}

void test_eb3a_polls_pack_voltage_register() {
  bool found = false;

  for (int i = 0; i < sizeof(bluetti_polling_command) / sizeof(device_field_data_t); i++) {
    if (bluetti_polling_command[i].f_page == 0x00 && bluetti_polling_command[i].f_offset == 0x62) {
      found = true;
      TEST_ASSERT_EQUAL(1, bluetti_polling_command[i].f_size);
    }
  }

  TEST_ASSERT_TRUE(found);
}

int main(int argc, char **argv) {
  UNITY_BEGIN();
  RUN_TEST(test_eb3a_publishes_pack_voltage);
  RUN_TEST(test_eb3a_polls_pack_voltage_register);
  return UNITY_END();
}
