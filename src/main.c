#include <string.h>
#include "esp_log.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "driver/gpio.h"

// Define the credentials for your Wi-Fi network
#include "creds.h"

// Redefine QDP_MALLOC and QDP_FREE to use FreeRTOS memory management functions
// Not necessary if you're using the default malloc and free functions or
// if you're doing everything statically.
// #define QDP_MALLOC(size) pvPortMalloc(size)
// #define QDP_FREE(ptr) vPortFree(ptr)
#include "qdp.h"

#define TCP_SERVER_IP   "192.168.1.66"  
#define TCP_SERVER_PORT 12345
#define MAX_RETRY       5

#define DEVICE_ID_ESP32   (0xDEADBEEF)
#define DEVICE_ID_BUTTON  (DEVICE_ID_ESP32 + 1)

#define BUTTON_GPIO GPIO_NUM_0

static const char *TAG = "QDP_Client";
static int s_retry_num = 0;
static EventGroupHandle_t wifi_event_group;
const int WIFI_CONNECTED_BIT = BIT0;

static QDPHandle  _qdp;
static QDPHandle* qdp = &_qdp;

static void set_socket_nonblocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) {
        ESP_LOGE(TAG, "Failed to get socket flags");
        return;
    }
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
        ESP_LOGE(TAG, "Failed to set socket to non-blocking");
    }
}

static int recv_msg(QDPMessage* msg, void* ctx) {
    int sock = *(int*)ctx;
    int len = recv(sock, msg->buffer + msg->buffered, msg->capacity - 1, 0);
    if (len < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // No data available right now, try again later
            return 0;
        }

        ESP_LOGE(TAG, "recv failed: errno %d", errno);
        return -1;
    } else if (len == 0) {
        ESP_LOGI(TAG, "Connection closed");
        return -1;
    }

    msg->buffered = ( msg->buffered + len ) % msg->capacity;
    ESP_LOGI(TAG, "Received %d bytes", len);

    return 0;
}

static int send_msg(QDPMessage* msg, void* ctx) {
    int sock = *(int*)ctx;
    
    if (msg->validity != QDP_MESSAGE_VALID) {
        ESP_LOGE(TAG, "Invalid message");
        return 0;
    }

    uint32_t length = qdp_message_calc_length(msg);
    uint32_t total_sent = 0;
    
    while (total_sent < length) {
        int sent = send(sock, msg->buffer + total_sent, length - total_sent, 0);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // No space in the send buffer, retry later
                continue;
            }
            ESP_LOGE(TAG, "send failed: errno %d", errno);
            return -1;
        }
        total_sent += sent;
    }

    ESP_LOGI(TAG, "Sent %lu bytes", total_sent);

    return 0;
}

typedef struct {
    int pin;
    bool pushed;
} Button;

Button btn = {
    .pin = BUTTON_GPIO,
    .pushed = false
};

void button_init(Button *btn)
{
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << btn->pin),
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE
    };
    gpio_config(&io_conf);
}

void button_get(QDPPayload *payload, void *ctx)
{
    Button *btn = (Button *)ctx;
    qdp_payload_set_int(payload, btn->pushed);
}

bool button_changed(void *ctx)
{
    Button *btn = (Button *)ctx;

    int pushed = gpio_get_level(btn->pin);
    if (pushed != btn->pushed) {
        btn->pushed = pushed;
        return true;
    }
    
    return false;
}

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    ESP_LOGI(TAG, "wifi_event_handler");

    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_num < MAX_RETRY) {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "Retrying to connect to the WiFi...");
        } else {
            xEventGroupClearBits(wifi_event_group, WIFI_CONNECTED_BIT);
        }
        ESP_LOGI(TAG, "Failed to connect to the WiFi.");
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *) event_data;
        ESP_LOGI(TAG, "Got IP:" IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void wifi_init_sta()
{
    wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Wi-Fi initialization complete.");
}

static void tcp_client_task(void *pvParameters)
{
    struct sockaddr_in dest_addr;

    dest_addr.sin_addr.s_addr = inet_addr(TCP_SERVER_IP);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(TCP_SERVER_PORT);

    while (1) {
        EventBits_t bits = xEventGroupWaitBits(wifi_event_group, WIFI_CONNECTED_BIT,
                                               pdFALSE, pdTRUE, portMAX_DELAY);
        if (bits & WIFI_CONNECTED_BIT) {
            int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
            if (sock < 0) {
                ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
                vTaskDelay(pdMS_TO_TICKS(5000));
                continue;
            }
            ESP_LOGI(TAG, "Socket created, connecting to %s:%d", TCP_SERVER_IP, TCP_SERVER_PORT);

            int err = connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            if (err != 0) {
                ESP_LOGE(TAG, "Socket unable to connect: errno %d", errno);
                close(sock);
                vTaskDelay(pdMS_TO_TICKS(5000));
                continue;
            }
            ESP_LOGI(TAG, "Successfully connected");

            set_socket_nonblocking(sock);

            qdp->recv.fn = recv_msg;
            qdp->recv.ctx = &sock;
            qdp->send.fn = send_msg;
            qdp->send.ctx = &sock;
            while (qdp_do_tick(qdp) == 0) {
                vTaskDelay(pdMS_TO_TICKS(10));
            }
            qdp->recv.fn = NULL;
            qdp->recv.ctx = NULL;
            qdp->send.fn = NULL;
            qdp->send.ctx = NULL;

            if (sock != -1) {
                ESP_LOGE(TAG, "Shutting down socket and restarting...");
                shutdown(sock, 0);
                close(sock);
            }
        }
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
    vTaskDelete(NULL);
}

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    
    button_init(&btn);

    qdp_init(qdp, DEVICE_ID_ESP32);
    if (qdp == NULL) {
        ESP_LOGE(TAG, "Failed to initialize QDP");
        return;
    }

    {
        QDPDevice* dev = qdp_device_register(qdp, DEVICE_ID_BUTTON);
        dev->get.fn = button_get;
        dev->get.ctx = &btn;
        dev->changed.fn = button_changed;
        dev->changed.ctx = &btn;
    }

    wifi_init_sta();

    xTaskCreate(&tcp_client_task, "tcp_client_task", 4096, NULL, 5, NULL);
}
