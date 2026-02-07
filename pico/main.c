#include <stdio.h>
#include <string.h>

#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "lwip/tcp.h"
#include "lwip/pbuf.h"
#include "lwip/ip_addr.h"

#define POLL_INTERVAL_MS 10000
#define HTTP_TIMEOUT_MS  5000
#define RESPONSE_BUF_SIZE 512

typedef struct {
    struct tcp_pcb *pcb;
    char response[RESPONSE_BUF_SIZE];
    int response_len;
    bool complete;
    bool connected;
    int result;
} http_request_t;

static void http_close(http_request_t *req) {
    if (req->pcb) {
        cyw43_arch_lwip_begin();
        tcp_arg(req->pcb, NULL);
        tcp_recv(req->pcb, NULL);
        tcp_err(req->pcb, NULL);
        tcp_sent(req->pcb, NULL);
        tcp_close(req->pcb);
        cyw43_arch_lwip_end();
        req->pcb = NULL;
    }
}

static int parse_grid_status(const char *response, int len) {
    const char *body = NULL;
    for (int i = 0; i < len - 3; i++) {
        if (response[i] == '\r' && response[i+1] == '\n' &&
            response[i+2] == '\r' && response[i+3] == '\n') {
            body = &response[i + 4];
            break;
        }
    }

    if (!body) return -1;

    if (strncmp(body, "UP", 2) == 0) return 1;
    if (strncmp(body, "DOWN", 4) == 0) return 0;
    return -1;
}

static err_t http_recv_cb(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    http_request_t *req = (http_request_t *)arg;

    if (!p) {
        req->result = parse_grid_status(req->response, req->response_len);
        req->complete = true;
        tcp_close(pcb);
        req->pcb = NULL;
        return ERR_OK;
    }

    int space = RESPONSE_BUF_SIZE - 1 - req->response_len;
    if (space > 0) {
        int copy = (int)p->tot_len < space ? (int)p->tot_len : space;
        pbuf_copy_partial(p, req->response + req->response_len, copy, 0);
        req->response_len += copy;
        req->response[req->response_len] = '\0';
    }

    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

static err_t http_sent_cb(void *arg, struct tcp_pcb *pcb, u16_t len) {
    return ERR_OK;
}

static err_t http_connected_cb(void *arg, struct tcp_pcb *pcb, err_t err) {
    http_request_t *req = (http_request_t *)arg;

    if (err != ERR_OK) {
        req->result = -1;
        req->complete = true;
        return err;
    }

    req->connected = true;

    static const char request[] =
        "GET /api/grid HTTP/1.0\r\n"
        "Host: " SERVER_IP "\r\n"
        "Connection: close\r\n"
        "\r\n";

    tcp_write(pcb, request, sizeof(request) - 1, TCP_WRITE_FLAG_COPY);
    tcp_output(pcb);

    return ERR_OK;
}

static void http_err_cb(void *arg, err_t err) {
    http_request_t *req = (http_request_t *)arg;
    req->pcb = NULL;
    req->result = -1;
    req->complete = true;
}

static int check_grid(void) {
    http_request_t req;
    memset(&req, 0, sizeof(req));
    req.result = -1;

    cyw43_arch_lwip_begin();

    struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
    if (!pcb) {
        cyw43_arch_lwip_end();
        return -1;
    }

    req.pcb = pcb;
    tcp_arg(pcb, &req);
    tcp_recv(pcb, http_recv_cb);
    tcp_sent(pcb, http_sent_cb);
    tcp_err(pcb, http_err_cb);

    ip_addr_t server_ip;
    ipaddr_aton(SERVER_IP, &server_ip);

    err_t err = tcp_connect(pcb, &server_ip, SERVER_PORT, http_connected_cb);
    cyw43_arch_lwip_end();

    if (err != ERR_OK) {
        http_close(&req);
        return -1;
    }

    absolute_time_t timeout = make_timeout_time_ms(HTTP_TIMEOUT_MS);
    while (!req.complete && !time_reached(timeout)) {
        sleep_ms(10);
    }

    if (!req.complete) {
        http_close(&req);
        return -1;
    }

    http_close(&req);
    return req.result;
}

static bool wifi_connect(void) {
    printf("Connecting to WiFi \"%s\"...\n", WIFI_SSID);

    int err = cyw43_arch_wifi_connect_timeout_ms(
        WIFI_SSID, WIFI_PASSWORD, CYW43_AUTH_WPA2_AES_PSK, 30000
    );

    if (err) {
        printf("WiFi connection failed (err %d)\n", err);
        return false;
    }

    printf("WiFi connected, IP: %s\n",
        ipaddr_ntoa(netif_ip4_addr(netif_list)));
    return true;
}

int main(void) {
    stdio_init_all();
    sleep_ms(2000);

    printf("Grid monitor starting\n");
    printf("Server: %s:%d\n", SERVER_IP, SERVER_PORT);

    if (cyw43_arch_init()) {
        printf("CYW43 init failed\n");
        return 1;
    }

    cyw43_arch_enable_sta_mode();

    while (!wifi_connect()) {
        printf("Retrying in 5s...\n");
        sleep_ms(5000);
    }

    bool led_state = false;

    while (true) {
        int status = check_grid();

        if (status == 1) {
            printf("Grid UP\n");
            cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);
            led_state = true;
        } else if (status == 0) {
            printf("Grid DOWN\n");
            cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 0);
            led_state = false;
        } else {
            printf("Server unreachable or unknown status\n");
        }

        sleep_ms(POLL_INTERVAL_MS);
    }
}
