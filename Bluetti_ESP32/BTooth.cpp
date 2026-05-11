#include "BluettiConfig.h"
#include "BTooth.h"
#include "BluettiEncryption.h"
#include "utils.h"
#include "PayloadParser.h"
#include "BWifi.h"
#include "display.h"

#include <algorithm>
#include <cstring>
#include <vector>

int pollTick = 0;

struct command_handle {
  uint8_t page;
  uint8_t offset;
  int length;
};

struct bt_notify_packet_t {
  size_t length;
  uint8_t data[600];
};

QueueHandle_t commandHandleQueue;
QueueHandle_t sendQueue;
QueueHandle_t notifyQueue;

unsigned long lastBTMessage = 0;
static BluettiEncryption bluettiEncryption;
static BluettiEncryption::State lastLoggedEncryptionState = BluettiEncryption::FAILED;

static void logHexLine(const char* prefix, const uint8_t* data, size_t length) {
#ifdef DEBUG
  Serial.print(prefix);
  Serial.print(F(" len="));
  Serial.print(length);
  Serial.print(F(" data="));
  Serial.println(bluetti_hex(data, length).c_str());
#else
  (void)prefix;
  (void)data;
  (void)length;
#endif
}

static void logEncryptionStateIfChanged() {
#ifdef DEBUG
  if (bluettiEncryption.state() != lastLoggedEncryptionState) {
    Serial.print(F("[BT_STATE] encryption -> "));
    Serial.println(bluettiEncryption.stateName());
    lastLoggedEncryptionState = bluettiEncryption.state();
  }
#endif
}

static bool matchesTargetMac(BLEAdvertisedDevice *advertisedDevice) {
#ifdef BLUETTI_TARGET_MAC
  return strcasecmp(advertisedDevice->getAddress().toString().c_str(), BLUETTI_TARGET_MAC) == 0;
#else
  (void)advertisedDevice;
  return false;
#endif
}

static bool hasValidModbusCrc(const uint8_t* data, size_t length) {
  if (length < 4) {
    return false;
  }
  const uint16_t expected = static_cast<uint16_t>(data[length - 2]) | (static_cast<uint16_t>(data[length - 1]) << 8);
  return modbus_crc(const_cast<uint8_t*>(data), length - 2) == expected;
}

class MyClientCallback : public BLEClientCallbacks {
  void onConnect(BLEClient* pclient) {
    Serial.println(F("BLE - onConnect"));
     #ifdef DISPLAYSSD1306
      disp_setBlueTooth(true);
     #endif
  }

  void onDisconnect(BLEClient* pclient) {
    connected = false;
    bluettiEncryption.reset();
    pollTick = 0;
    if (commandHandleQueue != nullptr) {
      xQueueReset(commandHandleQueue);
    }
    if (notifyQueue != nullptr) {
      xQueueReset(notifyQueue);
    }
    lastLoggedEncryptionState = BluettiEncryption::FAILED;
    Serial.println(F("BLE - onDisconnect"));
    #ifdef DISPLAYSSD1306
      disp_setBlueTooth(false);
    #endif
    #ifdef RELAISMODE
      #ifdef DEBUG
        Serial.println(F("deactivate relais contact"));
      #endif
      digitalWrite(RELAIS_PIN, RELAIS_LOW);
    #endif
  }
};

/**
 * Scan for BLE servers and find the first one that advertises the service we are looking for.
 */
class BluettiAdvertisedDeviceCallbacks: public BLEAdvertisedDeviceCallbacks {
 /**
   * Called for each advertising BLE server.
   */
  void onResult(BLEAdvertisedDevice *advertisedDevice) {
    Serial.print(F("[BLE] Advertised Device found: "));
    Serial.println(advertisedDevice->toString().c_str());

    ESPBluettiSettings settings = get_esp32_bluetti_settings();
    bool matchesMac = matchesTargetMac(advertisedDevice);
    bool matchesName = strcmp(advertisedDevice->getName().c_str(), settings.bluetti_device_id) == 0;
    bool hasBluettiService = advertisedDevice->haveServiceUUID() && advertisedDevice->isAdvertisingService(serviceUUID);

    // We have found a device, let us now see if it contains the service we are looking for.
    if ((matchesMac || matchesName) && (hasBluettiService || matchesMac)) {
      Serial.print(F("[BT_STATE] scan -> connect_requested reason="));
      Serial.println(matchesMac ? F("mac_match") : F("name_match"));
      BLEDevice::getScan()->stop();
      bluettiDevice = advertisedDevice;
      doConnect = true;
      doScan = true;
    }
  } 
};

void initBluetooth(){
  bluettiEncryption.reset();
  logEncryptionStateIfChanged();
  BLEDevice::init("");
  BLEScan* pBLEScan = BLEDevice::getScan();
  pBLEScan->setAdvertisedDeviceCallbacks(new BluettiAdvertisedDeviceCallbacks());
  pBLEScan->setInterval(1349);
  pBLEScan->setWindow(449);
  pBLEScan->setActiveScan(true);
  pBLEScan->start(5, false);
  
  commandHandleQueue = xQueueCreate( 5, sizeof(bt_command_t ) );
  sendQueue = xQueueCreate( 5, sizeof(bt_command_t) );
  notifyQueue = xQueueCreate( 5, sizeof(bt_notify_packet_t) );
}


static void handleBTNotifyPacket(const uint8_t* pData, size_t length) {
    std::vector<uint8_t> write_response;
    std::vector<uint8_t> plaintext_response;
    const bool processed = bluettiEncryption.processIncoming(pData, length, write_response, plaintext_response);
    logEncryptionStateIfChanged();

    if (!processed) {
      Serial.print(F("[ENC] process error: "));
      Serial.println(bluettiEncryption.lastError());
      return;
    }

    if (!write_response.empty()) {
      logHexLine("[ENC] handshake tx", write_response.data(), write_response.size());
      pRemoteWriteCharacteristic->writeValue(write_response.data(), write_response.size(), false);
      return;
    }

    if (plaintext_response.empty()) {
      Serial.println(F("[ENC] handshake notification handled"));
      return;
    }

    logHexLine("[BT_RX] decrypted", plaintext_response.data(), plaintext_response.size());
    bt_command_t command_handle;
    bool hasCommandHandle = xQueueReceive(commandHandleQueue, &command_handle, 500) == pdTRUE;

    if (!hasValidModbusCrc(plaintext_response.data(), plaintext_response.size())) {
      Serial.println(F("[BT_RX] decrypted response crc=invalid"));
      return;
    }

    Serial.print(F("[BT_RX] decrypted response crc=ok function=0x"));
    Serial.println(plaintext_response.size() > 1 ? plaintext_response[1] : 0, HEX);

    if(hasCommandHandle){
      parse_bluetooth_data(command_handle.page, command_handle.offset, plaintext_response.data(), plaintext_response.size());
    } else {
      Serial.println(F("[BT_RX] no pending command metadata for decrypted response"));
    }
   
}

static void notifyCallback(
  BLERemoteCharacteristic* pBLERemoteCharacteristic,
  uint8_t* pData,
  size_t length,
  bool isNotify) {

    (void)pBLERemoteCharacteristic;
    (void)isNotify;

    bt_notify_packet_t packet;
    packet.length = std::min(length, sizeof(packet.data));
    memcpy(packet.data, pData, packet.length);

    if (xQueueSend(notifyQueue, &packet, 0) != pdTRUE) {
      Serial.println(F("[BT_RX] notify queue full, dropping packet"));
    }
}

static void handleBTNotifyQueue() {
  bt_notify_packet_t packet;
  while (xQueueReceive(notifyQueue, &packet, 0) == pdTRUE) {
    logHexLine("[BT_RX] notify", packet.data, packet.length);
    handleBTNotifyPacket(packet.data, packet.length);
  }
}

bool connectToServer() {
    Serial.print(F("[BT] Forming a connection to "));
    Serial.println(bluettiDevice->getAddress().toString().c_str());

    BLEDevice::setMTU(517); // set client to request maximum MTU from server (default is 23 otherwise)
    BLEClient*  pClient  = BLEDevice::createClient();
    Serial.println(F("[BT] - Created client"));

    pClient->setClientCallbacks(new MyClientCallback());

    // Connect to the remove BLE Server.
    pClient->connect(bluettiDevice);  // if you pass BLEAdvertisedDevice instead of address, it will be recognized type of peer device address (public or private)
    Serial.println(F("[BT] - Connected to server"));
    // pClient->setMTU(517); //set client to request maximum MTU from server (default is 23 otherwise)
  
    // Obtain a reference to the service we are after in the remote BLE server.
    BLERemoteService* pRemoteService = pClient->getService(serviceUUID);
    if (pRemoteService == nullptr) {
      Serial.print(F("[BT] Failed to find our service UUID: "));
      Serial.println(serviceUUID.toString().c_str());
      pClient->disconnect();
      return false;
    }
    Serial.println(F("[BT] - Found our service"));


    // Obtain a reference to the characteristic in the service of the remote BLE server.
    pRemoteWriteCharacteristic = pRemoteService->getCharacteristic(WRITE_UUID);
    if (pRemoteWriteCharacteristic == nullptr) {
      Serial.print(F("[BT] Failed to find our characteristic UUID: "));
      Serial.println(WRITE_UUID.toString().c_str());
      pClient->disconnect();
      return false;
    }
    Serial.println(F("[BT] - Found our Write characteristic"));

        // Obtain a reference to the characteristic in the service of the remote BLE server.
    pRemoteNotifyCharacteristic = pRemoteService->getCharacteristic(NOTIFY_UUID);
    if (pRemoteNotifyCharacteristic == nullptr) {
      Serial.print(F("[BT] Failed to find our characteristic UUID: "));
      Serial.println(NOTIFY_UUID.toString().c_str());
      pClient->disconnect();
      return false;
    }
    Serial.println(F("[BT] - Found our Write characteristic"));

    // Read the value of the characteristic.
    if(pRemoteWriteCharacteristic->canRead()) {
      std::string value = pRemoteWriteCharacteristic->readValue();
      Serial.print(F("[BT] The characteristic value was: "));
      Serial.println(value.c_str());
    }

    if(pRemoteNotifyCharacteristic->canNotify())
      pRemoteNotifyCharacteristic->registerForNotify(notifyCallback);

    bluettiEncryption.reset();
    pollTick = 0;
    xQueueReset(commandHandleQueue);
    xQueueReset(notifyQueue);
    logEncryptionStateIfChanged();
    connected = true;
     #ifdef RELAISMODE
      #ifdef DEBUG
        Serial.println(F("[BT] activate relais contact"));
      #endif
      digitalWrite(RELAIS_PIN, RELAIS_HIGH);
    #endif

    return true;
}


void handleBTCommandQueue(){

    bt_command_t command;
    if(xQueueReceive(sendQueue, &command, 0)) {
      
#ifdef DEBUG
    Serial.print("[BT] Write Request FF02 - Value: ");
    
    for(int i=0; i<8; i++){
       if ( i % 2 == 0){ Serial.print(" "); };
       Serial.printf("%02x", ((uint8_t*)&command)[i]);
    }
    
    Serial.println("");
#endif
      if (!bluettiEncryption.isReadyForCommands()) {
        Serial.print(F("[BT_STATE] skip queued command, encryption="));
        Serial.println(bluettiEncryption.stateName());
        return;
      }

      std::vector<uint8_t> encrypted;
      if (!bluettiEncryption.encryptCommand((uint8_t*)&command, sizeof(command), encrypted)) {
        Serial.print(F("[ENC] command encrypt error: "));
        Serial.println(bluettiEncryption.lastError());
        return;
      }

      logHexLine("[BT] Write Request FF02 encrypted", encrypted.data(), encrypted.size());
      pRemoteWriteCharacteristic->writeValue(encrypted.data(), encrypted.size(), true);
 
     };  
}

void sendBTCommand(bt_command_t command){
#if defined(READ_ONLY_MODE) && READ_ONLY_MODE
    Serial.println(F("[BT] read-only mode: ignoring outbound write command"));
    (void)command;
#else
    bt_command_t cmd = command;
    xQueueSend(sendQueue, &cmd, 0);
#endif
}

void handleBluetooth(){

  if (doConnect == true) {
    if (connectToServer()) {
      Serial.println(F("We are now connected to the Bluetti BLE Server."));
    } else {
      Serial.println(F("We have failed to connect to the server; there is nothing more we will do."));
    }
    doConnect = false;
  }

  if ((millis() - lastBTMessage) > (MAX_DISCONNECTED_TIME_UNTIL_REBOOT * 60000)){ 
    Serial.println(F("[BT] disconnected over allowed limit, reboot device"));
    #ifdef SLEEP_TIME_ON_BT_NOT_AVAIL
        esp_deep_sleep_start();
    #else
        ESP.restart();
    #endif
  }

  if (connected) {
    handleBTNotifyQueue();
    logEncryptionStateIfChanged();

    // poll for device state
    if (bluettiEncryption.isReadyForCommands() && millis() - lastBTMessage > BLUETOOTH_QUERY_MESSAGE_DELAY){

       bt_command_t command;
       command.prefix = 0x01;
       command.field_update_cmd = 0x03;
       command.page = bluetti_polling_command[pollTick].f_page;
       command.offset = bluetti_polling_command[pollTick].f_offset;
       command.len = (uint16_t) bluetti_polling_command[pollTick].f_size << 8;
       command.check_sum = modbus_crc((uint8_t*)&command,6);

       std::vector<uint8_t> encrypted;
       if (!bluettiEncryption.encryptCommand((uint8_t*)&command, sizeof(command), encrypted)) {
          Serial.print(F("[ENC] poll encrypt error: "));
          Serial.println(bluettiEncryption.lastError());
       } else {
          Serial.print(F("[BT_POLL] req page=0x"));
          Serial.print(command.page, HEX);
          Serial.print(F(" offset=0x"));
          Serial.print(command.offset, HEX);
          Serial.print(F(" words="));
          Serial.print(bluetti_polling_command[pollTick].f_size);
          Serial.print(F(" encrypted_len="));
          Serial.println(encrypted.size());

          if (xQueueSend(commandHandleQueue, &command, 0) != pdTRUE) {
            bt_command_t dropped;
            xQueueReceive(commandHandleQueue, &dropped, 0);
            xQueueSend(commandHandleQueue, &command, 0);
            Serial.println(F("[BT_POLL] pending command queue full, dropped oldest metadata"));
          }
          pRemoteWriteCharacteristic->writeValue(encrypted.data(), encrypted.size(), true);
       }

       if (pollTick == sizeof(bluetti_polling_command)/sizeof(device_field_data_t)-1 ){
           pollTick = 0;
       } else {
           pollTick++;
       }
            
      lastBTMessage = millis();
    } else if (!bluettiEncryption.isReadyForCommands()) {
      static unsigned long previousWaitLog = 0;
      if (millis() - previousWaitLog > 5000) {
        Serial.print(F("[BT_STATE] waiting for encryption handshake state="));
        Serial.println(bluettiEncryption.stateName());
        previousWaitLog = millis();
      }
    }

    handleBTCommandQueue();
    
  }else if(doScan){
    BLEDevice::getScan()->start(0);
  }
}

void btResetStack()
{
  connected=false;

}

bool isBTconnected(){
  return connected;
}

unsigned long getLastBTMessageTime(){
    return lastBTMessage;
}


