# Elliptic-Curve-on-ESP32

Takes temperature and pressure's mesure with a BMP180 and ESP32 module.

### ESP32

To compile, build and flash ESP32 project see [here](https://github.com/espressif/esp-idf)

### Connection between ESP32 module and BMP180


* Connect VIN pin of BMP180 with 3v3 pin on ESP32
* Connect GND pin of BMP180 with GND pin on ESP32
* Connect SCL pin of BMP180 with IO23 pin on ESP32
* Connect SDA pin of BMP180 with IO22 pin on ESP32

### Cryptographic function

Samples are encrypted with AES-GCM 256 bits. Symetric key is sent to the receiver by being encrypted following ECIES schema. uECC files from ESP32's library is used for the elliptic curve cryptography and mbdetls/aes.h is used for AES-GCM.

### First connection between ESP32 and Server

ESP32 and server wich receives datas must be connected on the same WiFi network. When connection is done, the server must send first his ECIES public key in compressed format (ie begining with 0x40). Then ESP32 sends a packet with the symetric key encrypted with ECIES schema. The used elliptic curve is secp256r1.


### Sending sample

ESP32 bufferizes 10 samples and encrypts them with AES-GCM 256 bits. A local timestamp is added to the sample.


### Files

ecc.c and ecc.h perform all cryptography's function. bmp180.c and bmp180.h do the sample. Those files are not mine and can be found at https://github.com/nkolban/esp32-snippets/blob/master/hardware/temperature%20and%20pressure/bmp180.c. main.c connects to the WiFi network and launchs the two tasks:

* Generates and sends the encrypted symetric key.
* Samples and encrypt temperature and pressure.


#### PS
This project is very specific but i put it on github more for the cryptographic example than to make it functionnal for another user.
