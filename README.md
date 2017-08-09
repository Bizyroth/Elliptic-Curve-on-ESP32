# Elliptic-Curve-on-ESP32

Takes temperature and pressure's mesure with a BMP180 and ESP32 module.

### Connection between ESP32 module and BMP180

Branch VIN pin of BMP180 with 3v3 pin on ESP32
Branch GND pin of BMP180 with GND pin on ESP32
Branch SCL pin of BMP180 with IO23 pin on ESP32
Branch SDA pin of BMP180 with IO22 pin on ESP32

### First connection between ESP32 and Server

ESP32 and server wich receive data must be connected on the same WiFi network. When connection is done, the server must send first his ECIES public Key to compressed format (ie beginiing with 0x40).
