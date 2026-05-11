#ifndef HA_DISCOVERY_H
#define HA_DISCOVERY_H

#include "DeviceType.h"

#include <string>

struct HADiscoveryDevice {
  std::string identifier;
  std::string name;
  std::string model;
  std::string mac_address;
};

std::string ha_sanitize_id(const std::string& value);
std::string ha_field_state_name(enum field_names field_name);
std::string ha_discovery_component(enum field_names field_name);
std::string ha_discovery_config_topic(
    const std::string& discovery_prefix,
    const std::string& device_id,
    enum field_names field_name);
std::string ha_discovery_payload(
    const HADiscoveryDevice& device,
    const std::string& mqtt_device_id,
    enum field_names field_name);

#endif
