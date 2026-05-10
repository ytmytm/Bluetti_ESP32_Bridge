#include <unity.h>

#include "HADiscovery.h"

void test_power_sensor_discovery_payload_has_power_metadata() {
  HADiscoveryDevice device = {
    "esp32bluetti",
    "Bluetti EB3A",
    "EB3A",
    "94:B9:7E:D5:6E:1C"
  };

  std::string topic = ha_discovery_config_topic("homeassistant", "esp32bluetti", DC_INPUT_POWER);
  std::string payload = ha_discovery_payload(device, "esp32bluetti", DC_INPUT_POWER);

  TEST_ASSERT_EQUAL_STRING("homeassistant/sensor/esp32bluetti_dc_input_power/config", topic.c_str());
  TEST_ASSERT_NOT_EQUAL(std::string::npos, payload.find("\"name\":\"DC Input Power\""));
  TEST_ASSERT_NOT_EQUAL(std::string::npos, payload.find("\"state_topic\":\"bluetti/esp32bluetti/state/dc_input_power\""));
  TEST_ASSERT_NOT_EQUAL(std::string::npos, payload.find("\"device_class\":\"power\""));
  TEST_ASSERT_NOT_EQUAL(std::string::npos, payload.find("\"state_class\":\"measurement\""));
  TEST_ASSERT_NOT_EQUAL(std::string::npos, payload.find("\"unit_of_measurement\":\"W\""));
  TEST_ASSERT_NOT_EQUAL(std::string::npos, payload.find("\"unique_id\":\"esp32bluetti_dc_input_power\""));
  TEST_ASSERT_NOT_EQUAL(std::string::npos, payload.find("\"manufacturer\":\"Bluetti\""));
  TEST_ASSERT_NOT_EQUAL(std::string::npos, payload.find("\"model\":\"EB3A\""));
}

void test_output_on_discovery_uses_binary_sensor_payloads() {
  HADiscoveryDevice device = {
    "esp32bluetti",
    "Bluetti EB3A",
    "EB3A",
    "94:B9:7E:D5:6E:1C"
  };

  std::string topic = ha_discovery_config_topic("homeassistant", "esp32bluetti", AC_OUTPUT_ON);
  std::string payload = ha_discovery_payload(device, "esp32bluetti", AC_OUTPUT_ON);

  TEST_ASSERT_EQUAL_STRING("homeassistant/binary_sensor/esp32bluetti_ac_output_on/config", topic.c_str());
  TEST_ASSERT_NOT_EQUAL(std::string::npos, payload.find("\"payload_on\":\"1\""));
  TEST_ASSERT_NOT_EQUAL(std::string::npos, payload.find("\"payload_off\":\"0\""));
  TEST_ASSERT_NOT_EQUAL(std::string::npos, payload.find("\"state_topic\":\"bluetti/esp32bluetti/state/ac_output_on\""));
}

void test_diagnostic_version_sensor_is_marked_diagnostic() {
  HADiscoveryDevice device = {
    "esp32bluetti",
    "Bluetti EB3A",
    "EB3A",
    "94:B9:7E:D5:6E:1C"
  };

  std::string payload = ha_discovery_payload(device, "esp32bluetti", ARM_VERSION);

  TEST_ASSERT_NOT_EQUAL(std::string::npos, payload.find("\"entity_category\":\"diagnostic\""));
  TEST_ASSERT_EQUAL(std::string::npos, payload.find("\"state_class\":\"measurement\""));
  TEST_ASSERT_EQUAL(std::string::npos, payload.find("\"unit_of_measurement\""));
}

void test_current_sensor_discovery_payload_has_amp_metadata() {
  HADiscoveryDevice device = {
    "esp32bluetti",
    "Bluetti EB3A",
    "EB3A",
    "94:B9:7E:D5:6E:1C"
  };

  std::string payload = ha_discovery_payload(device, "esp32bluetti", INTERNAL_DC_INPUT_CURRENT);

  TEST_ASSERT_NOT_EQUAL(std::string::npos, payload.find("\"device_class\":\"current\""));
  TEST_ASSERT_NOT_EQUAL(std::string::npos, payload.find("\"state_class\":\"measurement\""));
  TEST_ASSERT_NOT_EQUAL(std::string::npos, payload.find("\"unit_of_measurement\":\"A\""));
}

void test_discovery_payload_includes_availability_and_fits_mqtt_buffer() {
  HADiscoveryDevice device = {
    "esp32bluetti",
    "Bluetti EB3A",
    "EB3A",
    "94:B9:7E:D5:6E:1C"
  };

  std::string payload = ha_discovery_payload(device, "esp32bluetti", DC_INPUT_VOLTAGE);

  TEST_ASSERT_NOT_EQUAL(std::string::npos, payload.find("\"availability_topic\":\"bluetti/esp32bluetti/status\""));
  TEST_ASSERT_LESS_THAN(2048, payload.size());
}

int main(int argc, char **argv) {
  UNITY_BEGIN();
  RUN_TEST(test_power_sensor_discovery_payload_has_power_metadata);
  RUN_TEST(test_output_on_discovery_uses_binary_sensor_payloads);
  RUN_TEST(test_diagnostic_version_sensor_is_marked_diagnostic);
  RUN_TEST(test_current_sensor_discovery_payload_has_amp_metadata);
  RUN_TEST(test_discovery_payload_includes_availability_and_fits_mqtt_buffer);
  return UNITY_END();
}
