#include "HADiscovery.h"

#include <cctype>
#include <sstream>

namespace {

std::string json_escape(const std::string& value) {
  std::string escaped;
  escaped.reserve(value.size());
  for (char c : value) {
    switch (c) {
      case '\\':
        escaped += "\\\\";
        break;
      case '"':
        escaped += "\\\"";
        break;
      default:
        escaped += c;
        break;
    }
  }
  return escaped;
}

std::string json_pair(const char* key, const std::string& value) {
  return std::string("\"") + key + "\":\"" + json_escape(value) + "\"";
}

std::string friendly_name_from_state_name(const std::string& state_name) {
  std::string result;
  bool new_word = true;
  for (size_t i = 0; i < state_name.size(); i++) {
    char c = state_name[i];
    if (c == '_') {
      result += ' ';
      new_word = true;
      continue;
    }
    if (new_word) {
      result += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
      new_word = false;
    } else {
      result += c;
    }
  }

  const char* acronyms[] = {"Ac", "Dc", "Arm", "Dsp"};
  const char* replacements[] = {"AC", "DC", "ARM", "DSP"};
  const size_t lengths[] = {2, 2, 3, 3};
  for (size_t i = 0; i < 4; i++) {
    size_t pos = 0;
    while ((pos = result.find(acronyms[i], pos)) != std::string::npos) {
      result.replace(pos, lengths[i], replacements[i]);
      pos += lengths[i];
    }
  }

  return result;
}

bool is_power_field(enum field_names field_name) {
  return field_name == DC_INPUT_POWER ||
         field_name == AC_INPUT_POWER ||
         field_name == AC_OUTPUT_POWER ||
         field_name == DC_OUTPUT_POWER ||
         field_name == INTERNAL_DC_INPUT_POWER ||
         field_name == INTERNAL_POWER_ONE ||
         field_name == INTERNAL_POWER_TWO ||
         field_name == INTERNAL_POWER_THREE ||
         field_name == AC_INPUT_POWER_MAX ||
         field_name == AC_OUTPUT_POWER_MAX;
}

bool is_current_field(enum field_names field_name) {
  return field_name == INTERNAL_CURRENT_ONE ||
         field_name == INTERNAL_CURRENT_TWO ||
         field_name == INTERNAL_CURRENT_THREE ||
         field_name == INTERNAL_DC_INPUT_CURRENT ||
         field_name == AC_INPUT_CURRENT_MAX ||
         field_name == AC_OUTPUT_CURRENT_MAX;
}

bool is_voltage_field(enum field_names field_name) {
  return field_name == AC_INPUT_VOLTAGE ||
         field_name == DC_INPUT_VOLTAGE ||
         field_name == PACK_VOLTAGE ||
         field_name == INTERNAL_PACK_VOLTAGE ||
         field_name == INTERNAL_AC_VOLTAGE ||
         field_name == INTERNAL_DC_INPUT_VOLTAGE ||
         field_name == INTERNAL_CELL01_VOLTAGE ||
         field_name == INTERNAL_CELL02_VOLTAGE ||
         field_name == INTERNAL_CELL03_VOLTAGE ||
         field_name == INTERNAL_CELL04_VOLTAGE ||
         field_name == INTERNAL_CELL05_VOLTAGE ||
         field_name == INTERNAL_CELL06_VOLTAGE ||
         field_name == INTERNAL_CELL07_VOLTAGE ||
         field_name == INTERNAL_CELL08_VOLTAGE ||
         field_name == INTERNAL_CELL09_VOLTAGE ||
         field_name == INTERNAL_CELL10_VOLTAGE ||
         field_name == INTERNAL_CELL11_VOLTAGE ||
         field_name == INTERNAL_CELL12_VOLTAGE ||
         field_name == INTERNAL_CELL13_VOLTAGE ||
         field_name == INTERNAL_CELL14_VOLTAGE ||
         field_name == INTERNAL_CELL15_VOLTAGE ||
         field_name == INTERNAL_CELL16_VOLTAGE;
}

bool is_diagnostic_field(enum field_names field_name) {
  return field_name == DEVICE_TYPE ||
         field_name == SERIAL_NUMBER ||
         field_name == ARM_VERSION ||
         field_name == DSP_VERSION ||
         field_name == PACK_NUM_MAX ||
         field_name == PACK_NUM;
}

}  // namespace

std::string ha_sanitize_id(const std::string& value) {
  std::string sanitized;
  sanitized.reserve(value.size());
  for (char c : value) {
    unsigned char uc = static_cast<unsigned char>(c);
    if (std::isalnum(uc) || c == '_' || c == '-') {
      sanitized += static_cast<char>(std::tolower(uc));
    } else {
      sanitized += '_';
    }
  }
  return sanitized.empty() ? "bluetti" : sanitized;
}

std::string ha_field_state_name(enum field_names field_name) {
  switch(field_name) {
    case DC_OUTPUT_POWER:
      return "dc_output_power";
    case AC_OUTPUT_POWER:
      return "ac_output_power";
    case DC_OUTPUT_ON:
      return "dc_output_on";
    case AC_OUTPUT_ON:
      return "ac_output_on";
    case AC_OUTPUT_MODE:
      return "ac_output_mode";
    case POWER_GENERATION:
      return "power_generation";
    case TOTAL_BATTERY_PERCENT:
      return "total_battery_percent";
    case DC_INPUT_POWER:
      return "dc_input_power";
    case DC_INPUT_VOLTAGE:
      return "dc_input_voltage";
    case AC_INPUT_POWER:
      return "ac_input_power";
    case AC_INPUT_VOLTAGE:
      return "ac_input_voltage";
    case AC_INPUT_FREQUENCY:
      return "ac_input_frequency";
    case PACK_VOLTAGE:
      return "pack_voltage";
    case INTERNAL_PACK_VOLTAGE:
      return "internal_pack_voltage";
    case SERIAL_NUMBER:
      return "serial_number";
    case ARM_VERSION:
      return "arm_version";
    case DSP_VERSION:
      return "dsp_version";
    case DEVICE_TYPE:
      return "device_type";
    case UPS_MODE:
      return "ups_mode";
    case AUTO_SLEEP_MODE:
      return "auto_sleep_mode";
    case GRID_CHARGE_ON:
      return "grid_charge_on";
    case INTERNAL_AC_VOLTAGE:
      return "internal_ac_voltage";
    case INTERNAL_AC_FREQUENCY:
      return "internal_ac_frequency";
    case INTERNAL_CURRENT_ONE:
      return "internal_current_one";
    case INTERNAL_POWER_ONE:
      return "internal_power_one";
    case INTERNAL_CURRENT_TWO:
      return "internal_current_two";
    case INTERNAL_POWER_TWO:
      return "internal_power_two";
    case INTERNAL_CURRENT_THREE:
      return "internal_current_three";
    case INTERNAL_POWER_THREE:
      return "internal_power_three";
    case PACK_NUM_MAX:
      return "pack_max_num";
    case PACK_NUM:
      return "pack_num";
    case PACK_BATTERY_PERCENT:
      return "pack_battery_percent";
    case INTERNAL_DC_INPUT_VOLTAGE:
      return "internal_dc_input_voltage";
    case INTERNAL_DC_INPUT_POWER:
      return "internal_dc_input_power";
    case INTERNAL_DC_INPUT_CURRENT:
      return "internal_dc_input_current";
    case INTERNAL_CELL01_VOLTAGE:
      return "internal_cell01_voltage";
    case INTERNAL_CELL02_VOLTAGE:
      return "internal_cell02_voltage";
    case INTERNAL_CELL03_VOLTAGE:
      return "internal_cell03_voltage";
    case INTERNAL_CELL04_VOLTAGE:
      return "internal_cell04_voltage";
    case INTERNAL_CELL05_VOLTAGE:
      return "internal_cell05_voltage";
    case INTERNAL_CELL06_VOLTAGE:
      return "internal_cell06_voltage";
    case INTERNAL_CELL07_VOLTAGE:
      return "internal_cell07_voltage";
    case INTERNAL_CELL08_VOLTAGE:
      return "internal_cell08_voltage";
    case INTERNAL_CELL09_VOLTAGE:
      return "internal_cell09_voltage";
    case INTERNAL_CELL10_VOLTAGE:
      return "internal_cell10_voltage";
    case INTERNAL_CELL11_VOLTAGE:
      return "internal_cell11_voltage";
    case INTERNAL_CELL12_VOLTAGE:
      return "internal_cell12_voltage";
    case INTERNAL_CELL13_VOLTAGE:
      return "internal_cell13_voltage";
    case INTERNAL_CELL14_VOLTAGE:
      return "internal_cell14_voltage";
    case INTERNAL_CELL15_VOLTAGE:
      return "internal_cell15_voltage";
    case INTERNAL_CELL16_VOLTAGE:
      return "internal_cell16_voltage";
    case LED_MODE:
      return "led_mode";
    case POWER_OFF:
      return "power_off";
    case ECO_ON:
      return "eco_on";
    case ECO_SHUTDOWN:
      return "eco_shutdown";
    case CHARGING_MODE:
      return "charging_mode";
    case POWER_LIFTING_ON:
      return "power_lifting_on";
    case AC_INPUT_POWER_MAX:
      return "ac_input_power_max";
    case AC_INPUT_CURRENT_MAX:
      return "ac_input_current_max";
    case AC_OUTPUT_POWER_MAX:
      return "ac_output_power_max";
    case AC_OUTPUT_CURRENT_MAX:
      return "ac_output_current_max";
    case BATTERY_MIN_PERCENTAGE:
      return "battery_min_percentage";
    case AC_CHARGE_MAX_PERCENTAGE:
      return "ac_charge_max_percentage";
    default:
      return "unknown";
  }
}

std::string ha_discovery_component(enum field_names field_name) {
  if (field_name == AC_OUTPUT_ON || field_name == DC_OUTPUT_ON) {
    return "binary_sensor";
  }
  return "sensor";
}

std::string ha_discovery_config_topic(
    const std::string& discovery_prefix,
    const std::string& device_id,
    enum field_names field_name) {
  const std::string object_id = ha_sanitize_id(device_id + "_" + ha_field_state_name(field_name));
  return discovery_prefix + "/" + ha_discovery_component(field_name) + "/" + object_id + "/config";
}

std::string ha_discovery_payload(
    const HADiscoveryDevice& device,
    const std::string& mqtt_device_id,
    enum field_names field_name) {
  const std::string field = ha_field_state_name(field_name);
  const std::string unique_id = ha_sanitize_id(device.identifier + "_" + field);
  const std::string availability_topic = "bluetti/" + mqtt_device_id + "/status";

  std::ostringstream payload;
  payload << "{"
          << json_pair("name", friendly_name_from_state_name(field)) << ","
          << json_pair("unique_id", unique_id) << ","
          << json_pair("state_topic", "bluetti/" + mqtt_device_id + "/state/" + field) << ","
          << json_pair("availability_topic", availability_topic);

  if (ha_discovery_component(field_name) == "binary_sensor") {
    payload << "," << json_pair("payload_on", "1")
            << "," << json_pair("payload_off", "0")
            << "," << json_pair("device_class", "power");
  } else if (is_power_field(field_name)) {
    payload << "," << json_pair("device_class", "power")
            << "," << json_pair("state_class", "measurement")
            << "," << json_pair("unit_of_measurement", "W");
  } else if (is_voltage_field(field_name)) {
    payload << "," << json_pair("device_class", "voltage")
            << "," << json_pair("state_class", "measurement")
            << "," << json_pair("unit_of_measurement", "V");
  } else if (is_current_field(field_name)) {
    payload << "," << json_pair("device_class", "current")
            << "," << json_pair("state_class", "measurement")
            << "," << json_pair("unit_of_measurement", "A");
  } else if (field_name == TOTAL_BATTERY_PERCENT ||
             field_name == PACK_BATTERY_PERCENT ||
             field_name == BATTERY_MIN_PERCENTAGE ||
             field_name == AC_CHARGE_MAX_PERCENTAGE) {
    payload << "," << json_pair("device_class", "battery")
            << "," << json_pair("state_class", "measurement")
            << "," << json_pair("unit_of_measurement", "%");
  } else if (field_name == POWER_GENERATION) {
    payload << "," << json_pair("device_class", "energy")
            << "," << json_pair("state_class", "total_increasing")
            << "," << json_pair("unit_of_measurement", "kWh");
  } else if (field_name == AC_INPUT_FREQUENCY || field_name == INTERNAL_AC_FREQUENCY) {
    payload << "," << json_pair("device_class", "frequency")
            << "," << json_pair("state_class", "measurement")
            << "," << json_pair("unit_of_measurement", "Hz");
  } else if (is_diagnostic_field(field_name)) {
    payload << "," << json_pair("entity_category", "diagnostic");
  }

  payload << ",\"device\":{"
          << json_pair("identifiers", ha_sanitize_id(device.identifier)) << ","
          << json_pair("name", device.name) << ","
          << json_pair("manufacturer", "Bluetti") << ","
          << json_pair("model", device.model);
  if (!device.mac_address.empty()) {
    payload << ",\"connections\":[[\"mac\",\"" << json_escape(device.mac_address) << "\"]]";
  }
  payload << "}}";

  return payload.str();
}
