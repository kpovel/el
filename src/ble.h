#ifndef BLE_H
#define BLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "protocol.h"

typedef struct {
    char    name[64];
    char    address[18];
    char    serial[32];
    int     rssi;
    char    obj_path[256];
} EcoFlowDevice;

int ble_scan(EcoFlowDevice *devs, int max_devs, int timeout_sec);

typedef struct BLEConn BLEConn;
typedef void (*ble_status_cb)(const River3Status *status, void *user);

BLEConn *ble_connect(const char *device_address,
                     const char *device_sn,
                     const char *user_id,
                     ble_status_cb cb, void *cb_user);

int ble_run(BLEConn *conn, int timeout_sec);
void ble_stop(BLEConn *conn);
const River3Status *ble_latest_status(const BLEConn *conn);
bool ble_is_authenticated(const BLEConn *conn);
void ble_disconnect(BLEConn *conn);

#endif
