#ifndef BLE_H
#define BLE_H

#include <stdbool.h>
#include "protocol.h"

typedef void (*ble_status_cb)(const River3Status *status, void *user);

void ble_init(const char *address, const char *serial,
              const char *user_id, ble_status_cb cb, void *cb_user);

#endif
