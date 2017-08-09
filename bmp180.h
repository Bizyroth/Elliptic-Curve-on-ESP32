/*
 bmp180.h - BMP180 pressure sensor driver for ESP32
 This file is part of the ESP32 Everest Run project
 https://github.com/krzychb/esp32-everest-run
 Copyright (c) 2016 Krzysztof Budzynski <krzychb@gazeta.pl>
 This work is licensed under the Apache License, Version 2.0, January 2004
 See the file LICENSE for details.
*/

#ifndef BMP180_H
#define BMP180_H

#include "esp_err.h"
#include <driver/i2c.h>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include "sdkconfig.h"

#ifdef __cplusplus
extern "C" {
#endif

void echantillon(float * temperature, uint32_t * press);

#ifdef __cplusplus
}
#endif

#endif // BMP180_H
