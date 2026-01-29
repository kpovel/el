#ifndef BLE_H
#define BLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "protocol.h"

/* ── Discovered device ───────────────────────────────────────────── */

typedef struct {
    char    name[64];
    char    address[18]; /* "XX:XX:XX:XX:XX:XX" */
    char    serial[32];
    int     rssi;
    char    obj_path[256]; /* D-Bus object path */
} EcoFlowDevice;

/* ── Scan ────────────────────────────────────────────────────────── */

/*
 * Scan for EcoFlow devices. Blocks for timeout_sec seconds.
 * devs must point to an array of max_devs entries.
 * Returns number of devices found.
 */
int ble_scan(EcoFlowDevice *devs, int max_devs, int timeout_sec);

/* ── Connection & auth ───────────────────────────────────────────── */

typedef struct BLEConn BLEConn;

/* Status callback: called each time a status packet arrives. */
typedef void (*ble_status_cb)(const River3Status *status, void *user);

/*
 * Connect and authenticate. Returns NULL on failure.
 * device_address: "XX:XX:XX:XX:XX:XX"
 * device_sn:      serial number string
 * user_id:        EcoFlow user ID string
 * cb/cb_user:     optional status callback
 */
BLEConn *ble_connect(const char *device_address,
                     const char *device_sn,
                     const char *user_id,
                     ble_status_cb cb, void *cb_user);

/*
 * Run the event loop, processing incoming notifications.
 * Returns when disconnect or error occurs, or when ble_stop() is called.
 * timeout_sec: max time to run (0 = unlimited).
 */
int ble_run(BLEConn *conn, int timeout_sec);

/* Signal the event loop to stop after the current iteration. */
void ble_stop(BLEConn *conn);

/* Get the latest status (may be NULL if none received yet). */
const River3Status *ble_latest_status(const BLEConn *conn);

/* Check if authenticated. */
bool ble_is_authenticated(const BLEConn *conn);

/* Disconnect and free. */
void ble_disconnect(BLEConn *conn);

#endif /* BLE_H */
