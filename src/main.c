#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ble.h"
#include "protocol.h"

static BLEConn *g_conn = NULL;

static void sighandler(int sig)
{
    (void)sig;
    if (g_conn) ble_stop(g_conn);
}

static void timestamp_now(char *buf, size_t size)
{
    struct timespec ts;
    struct tm tm;
    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    strftime(buf, size, "%Y-%m-%dT%H:%M:%S", &tm);
}

static void print_status_text(const River3Status *s)
{
    char ts[64];
    timestamp_now(ts, sizeof(ts));
    const char *grid = river3_grid_available(s) ? "UP" : "DOWN";
    printf("[%s] Grid: %s | Battery: %d%% | AC In: %.0fW | AC Out: %.0fW\n",
           ts, grid, s->battery_level, s->ac_input_power, s->ac_output_power);
    fflush(stdout);
}

static void print_status_json(const River3Status *s)
{
    char ts[64];
    timestamp_now(ts, sizeof(ts));
    printf("{\"timestamp\":\"%s\","
           "\"grid_available\":%s,"
           "\"on_battery\":%s,"
           "\"battery_level\":%d,"
           "\"ac_input_power\":%.1f,"
           "\"ac_input_voltage\":%.1f,"
           "\"ac_output_power\":%.1f}\n",
           ts,
           river3_grid_available(s) ? "true" : "false",
           river3_on_battery(s) ? "true" : "false",
           s->battery_level,
           s->ac_input_power,
           s->ac_input_voltage,
           s->ac_output_power);
    fflush(stdout);
}

typedef struct {
    int   format_json;
    int   grid_was_up;
} MonitorState;

static void on_status(const River3Status *s, void *user)
{
    MonitorState *ms = user;
    int grid_up = river3_grid_available(s) ? 1 : 0;

    if (ms->grid_was_up >= 0 && grid_up != ms->grid_was_up) {
        const char *event = grid_up ? "GRID_RESTORED" : "GRID_LOST";
        char ts[64];
        timestamp_now(ts, sizeof(ts));

        if (ms->format_json) {
            printf("{\"timestamp\":\"%s\",\"event\":\"%s\","
                   "\"grid_available\":%s,\"battery_level\":%d}\n",
                   ts, event, grid_up ? "true" : "false", s->battery_level);
            fflush(stdout);
        } else {
            printf("\n*** [%s] %s ***\n", ts, event);
            printf("    Battery: %d%%\n", s->battery_level);
            if (!grid_up)
                printf("    Running on battery backup!\n");
            printf("\n");
            fflush(stdout);
        }
    } else {
        if (ms->format_json)
            print_status_json(s);
        else
            print_status_text(s);
    }

    ms->grid_was_up = grid_up;
}

static int cmd_scan(int timeout)
{
    printf("Scanning for EcoFlow devices (%ds)...\n", timeout);

    EcoFlowDevice devs[16];
    int count = ble_scan(devs, 16, timeout);

    if (count == 0) {
        printf("\nNo EcoFlow devices found.\n");
        printf("Make sure:\n");
        printf("  - Bluetooth is enabled\n");
        printf("  - Device is powered on\n");
        printf("  - EcoFlow app is disconnected\n");
        return 1;
    }

    printf("\nFound %d device(s):\n\n", count);
    for (int i = 0; i < count; i++) {
        printf("  Name:    %s\n", devs[i].name);
        printf("  Address: %s\n", devs[i].address);
        printf("  Serial:  %s\n", devs[i].serial);
        printf("  RSSI:    %d dBm\n", devs[i].rssi);
        printf("\n");
    }

    return 0;
}

typedef struct {
    int format_json;
    BLEConn *conn;
} CheckState;

static void on_check_status(const River3Status *s, void *user)
{
    CheckState *cs = user;
    if (cs->format_json)
        print_status_json(s);
    else
        print_status_text(s);
    ble_stop(cs->conn);
}

static int cmd_check(const char *address, const char *serial,
                     const char *user_id, int format_json)
{
    CheckState cs = {.format_json = format_json, .conn = NULL};

    BLEConn *conn = ble_connect(address, serial, user_id, on_check_status, &cs);
    if (!conn) {
        fprintf(stderr, "Failed to connect/authenticate\n");
        return 2;
    }

    cs.conn = conn;
    g_conn = conn;

    ble_run(conn, 5);

    const River3Status *s = ble_latest_status(conn);
    int rc;
    if (s) {
        rc = river3_grid_available(s) ? 0 : 1;
    } else {
        fprintf(stderr, "No status received\n");
        rc = 2;
    }

    ble_disconnect(conn);
    g_conn = NULL;
    return rc;
}

static int cmd_monitor(const char *address, const char *serial,
                       const char *user_id, int interval, int format_json)
{
    (void)interval;

    MonitorState ms = {.format_json = format_json, .grid_was_up = -1};

    BLEConn *conn = ble_connect(address, serial, user_id, on_status, &ms);
    if (!conn) {
        fprintf(stderr, "Failed to connect/authenticate\n");
        return 1;
    }

    g_conn = conn;

    printf("Monitoring grid status...\nPress Ctrl+C to stop.\n\n");
    fflush(stdout);

    ble_run(conn, 0);

    printf("\nStopping monitor...\n");
    ble_disconnect(conn);
    g_conn = NULL;
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "EcoFlow River 3 Grid Monitor\n\n"
        "Usage:\n"
        "  %s scan [--timeout N]\n"
        "  %s check ADDRESS --serial SN --user-id ID [--format text|json]\n"
        "  %s monitor ADDRESS --serial SN --user-id ID [--interval N] [--format text|json]\n"
        "\nEnvironment variables:\n"
        "  ECOFLOW_USER_ID    Your EcoFlow user ID\n"
        "  ECOFLOW_SERIAL     Device serial number\n",
        prog, prog, prog);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    signal(SIGINT,  sighandler);
    signal(SIGTERM, sighandler);

    const char *command = argv[1];

    if (strcmp(command, "scan") == 0) {
        int timeout = 10;

        static struct option long_opts[] = {
            {"timeout", required_argument, 0, 't'},
            {0, 0, 0, 0}
        };

        optind = 2;
        int c;
        while ((c = getopt_long(argc, argv, "t:", long_opts, NULL)) != -1) {
            if (c == 't') timeout = atoi(optarg);
        }

        return cmd_scan(timeout);
    }

    if (strcmp(command, "check") == 0 || strcmp(command, "monitor") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: ADDRESS is required\n");
            return 1;
        }

        const char *address = argv[2];
        const char *serial  = getenv("ECOFLOW_SERIAL");
        const char *user_id = getenv("ECOFLOW_USER_ID");
        const char *format  = "text";
        int interval = 10;

        static struct option long_opts[] = {
            {"serial",   required_argument, 0, 's'},
            {"user-id",  required_argument, 0, 'u'},
            {"format",   required_argument, 0, 'f'},
            {"interval", required_argument, 0, 'i'},
            {"timeout",  required_argument, 0, 't'},
            {0, 0, 0, 0}
        };

        optind = 3;
        int c;
        while ((c = getopt_long(argc, argv, "s:u:f:i:t:", long_opts, NULL)) != -1) {
            switch (c) {
            case 's': serial  = optarg; break;
            case 'u': user_id = optarg; break;
            case 'f': format  = optarg; break;
            case 'i': interval = atoi(optarg); break;
            default: break;
            }
        }

        if (!serial || !serial[0]) {
            fprintf(stderr, "Error: --serial is required (or set ECOFLOW_SERIAL)\n");
            return 1;
        }
        if (!user_id || !user_id[0]) {
            fprintf(stderr, "Error: --user-id is required (or set ECOFLOW_USER_ID)\n");
            return 1;
        }

        int json = (strcmp(format, "json") == 0);

        if (strcmp(command, "check") == 0)
            return cmd_check(address, serial, user_id, json);
        else
            return cmd_monitor(address, serial, user_id, interval, json);
    }

    usage(argv[0]);
    return 1;
}
