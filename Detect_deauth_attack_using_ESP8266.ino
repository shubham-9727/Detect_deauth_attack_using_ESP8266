#include <ESP8266WiFi.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
 
// include ESP8266 Non-OS SDK functions
extern "C" {
#include "user_interface.h"
}
 
// ===== SETTINGS ===== //
#define SCREEN_WIDTH 128    // OLED display width, in pixels
#define SCREEN_HEIGHT 64    // OLED display height, in pixels
#define SERIAL_BAUD 115200  // Baudrate for serial communication
#define CH_TIME 140         // Scan time (in ms) per channel
#define PKT_RATE 5          // Min. packets before it gets recognized as an attack
#define PKT_TIME 1          // Min. interval (CH_TIME*CH_RANGE) before it gets recognized as an attack
 
// Declaration for an SSD1306 display connected to I2C (SDA, SCL pins)
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1);

// Channels to scan on (US=1-11, EU=1-13, JAP=1-14)
const short channels[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13/*,14*/ };
 
// ===== Runtime variables ===== //
int ch_index { 0 };               // Current index of channel array
int packet_rate { 0 };            // Deauth packet counter (resets with each update)
int attack_counter { 0 };         // Attack counter
unsigned long update_time { 0 };  // Last update time
unsigned long ch_time { 0 };      // Last channel hop time
 
// ===== Sniffer function ===== //
void sniffer(uint8_t *buf, uint16_t len) {
  if (!buf || len < 28) return; // Drop packets without MAC header
 
  byte pkt_type = buf[12]; // second half of frame control field
  //byte* addr_a = &buf[16]; // first MAC address
  //byte* addr_b = &buf[22]; // second MAC address
 
  // If captured packet is a deauthentication or dissassociaten frame
  if (pkt_type == 0xA0 || pkt_type == 0xC0) {
    ++packet_rate;
  }
}
 
// ===== Attack detection functions ===== //
void attack_started() {
  
//  digitalWrite(LED_BUILTIN, LOW);   // Turn the LED on (HIGH)

  Serial.println("ATTACK DETECTED");
      display.setCursor(20, 0);
      display.setTextSize(1);
      display.setTextColor(WHITE);
      display.print("ATTACK DETECTED");
      display.display();
}
 
void attack_stopped() {
  
//  digitalWrite(LED_BUILTIN, HIGH);    // Turn the LED off (LOW

  Serial.println("ATTACK STOPPED");
      display.setCursor(20, 0);
      display.setTextSize(1);
      display.setTextColor(WHITE);
      display.print("ATTACK STOPPED");
      display.display();
}

// =====Intro=======//
void start(){
    display.clearDisplay();
    display.setTextColor(WHITE);
    display.setTextSize(2);
    display.setCursor(30, 10);
    display.print("Deauth");
    display.setCursor(20, 35);
    display.print("Detector");
    display.display();
    delay(3000);
    display.clearDisplay();
}
 
// ===== Setup ===== //
void setup() {
  Serial.begin(SERIAL_BAUD); // Start serial communication

  if(!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) { // Address 0x3D for 128x64
    Serial.println(F("SSD1306 allocation failed"));
    for(;;);
  }

  start();
  
  WiFi.disconnect();                   // Disconnect from any saved or active WiFi connections
  wifi_set_opmode(STATION_MODE);       // Set device to client/station mode
  wifi_set_promiscuous_rx_cb(sniffer); // Set sniffer function
  wifi_set_channel(channels[0]);        // Set channel
  wifi_promiscuous_enable(true);       // Enable sniffer

  
 }
 
// ===== Loop ===== //
void loop() {
  unsigned long current_time = millis(); // Get current time (in ms)
 
  // Update each second (or scan-time-per-channel * channel-range)
  if (current_time - update_time >= (sizeof(channels)*CH_TIME)) {
    update_time = current_time; // Update time variable
 
    // When detected deauth packets exceed the minimum allowed number
    if (packet_rate >= PKT_RATE) {
      ++attack_counter; // Increment attack counter
    }
    else {
        if (attack_counter >= PKT_TIME)
        attack_stopped();
          attack_counter = 0; // Reset attack counter
        }
 
    // When attack exceeds minimum allowed time
    if (attack_counter == PKT_TIME) {
      attack_started();
    }
    Serial.print("Packets/s: ");
    Serial.println(packet_rate);
    if (packet_rate > 0){
      display.setCursor(20, 0);
      display.setTextSize(1);
      display.setTextColor(WHITE);
      display.print("ATTACK DETECTED");
      display.display();
    }
    display.setTextColor(WHITE);
    display.setTextSize(2);
    display.setCursor(0, 15);
    display.print("Packets /s");
    display.println(" ");
    display.println(packet_rate);
    display.display();
    display.clearDisplay();
 
    packet_rate = 0; // Reset packet rate
  }
 
  // Channel hopping
  if (sizeof(channels) > 1 && current_time - ch_time >= CH_TIME) {
    ch_time = current_time; // Update time variable
 
    // Get next channel
    ch_index = (ch_index + 1) % (sizeof(channels) / sizeof(channels[0]));
    short ch = channels[ch_index];
 
    // Set channel
    //Serial.print("Set channel to ");
    //Serial.println(ch);
    wifi_set_channel(ch);
  }
}
