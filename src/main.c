#include <stdio.h>
#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "btstack.h"
#include "ble.h"
#include "protocol.h"

#ifndef ECOFLOW_ADDRESS
#error "Define ECOFLOW_ADDRESS"
#endif
#ifndef ECOFLOW_SERIAL
#error "Define ECOFLOW_SERIAL"
#endif
#ifndef ECOFLOW_USER_ID
#error "Define ECOFLOW_USER_ID"
#endif

static void on_status(const River3Status *s, void *user)
{
    (void)user;
    bool grid = river3_grid_available(s);
    printf("[STATUS] ac_in=%.1fW ac_in_v=%.1fV plugged=%d ac_out=%.1fW batt=%d%% grid=%d\n",
           s->ac_input_power, s->ac_input_voltage,
           s->ac_plugged_in, s->ac_output_power,
           s->battery_level, grid);
    cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, grid ? 1 : 0);
}

int main(void)
{
    stdio_init_all();
    if (cyw43_arch_init()) { printf("CYW43 init failed\n"); return 1; }

    l2cap_init();
    sm_init();
    gatt_client_init();

    ble_init(ECOFLOW_ADDRESS, ECOFLOW_SERIAL, ECOFLOW_USER_ID,
             on_status, NULL);

    hci_power_control(HCI_POWER_ON);
    btstack_run_loop_execute();
    return 0;
}
