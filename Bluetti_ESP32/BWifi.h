#ifndef BWIFI_H
#define BWIFI_H
#include "Arduino.h"
#include "config.h"

#ifndef DEFAULT_MQTT_SERVER
#define DEFAULT_MQTT_SERVER "127.0.0.1"
#endif

#ifndef DEFAULT_MQTT_PORT
#define DEFAULT_MQTT_PORT "1883"
#endif

#ifndef DEFAULT_BLUETTI_DEVICE_ID
#define DEFAULT_BLUETTI_DEVICE_ID "Bluetti Blutetooth Id"
#endif

typedef struct{
  int  salt = EEPROM_SALT;
  char mqtt_server[40] = DEFAULT_MQTT_SERVER;
  char mqtt_port[6]  = DEFAULT_MQTT_PORT;
  char mqtt_username[40] = "";
  char mqtt_password[40] = "";
  char bluetti_device_id[40] = DEFAULT_BLUETTI_DEVICE_ID;
  char ota_username[40] = "";
  char ota_password[40] = "";
} ESPBluettiSettings;

extern ESPBluettiSettings get_esp32_bluetti_settings();
extern void initBWifi(bool resetWifi);
extern void handleWebserver();
String processorWebsiteUpdates(const String& var);
extern void AddtoMsgView(String data);
  
#endif
