#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/unistd.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>

#include "driver/gpio.h"
#include "sdkconfig.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "freertos/event_groups.h"

#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_event.h"
#include "esp_system.h"
#include "esp_netif.h"
#include "esp_log.h"
#include "esp_spiffs.h"
#include "esp_sntp.h"
#include "nvs_flash.h"

#include "md5.h"
#include "mqtt_client.h"
#include "lwip/sockets.h"
#include "lwip/dns.h"
#include "lwip/netdb.h"

/* LED RED ON:        ESP32 turned on
 * LED BLUE FAST:     startup phase
 * LED BLUE ON:       connected to WiFi, not yet to MQTT broker
 * LED BLUE BLINK:    connected to MQTT broker and publishing */

/* --- LED --- */
#define BLINK_GPIO   2
#define BLINK_MODE   0
#define ON_MODE      1
#define OFF_MODE     2
#define STARTUP_MODE 3
static int BLINK_TIME_ON  = 5;
static int BLINK_TIME_OFF = 1000;

/* --- Config --- */
#define SSID_MAX_LEN  (32+1)
#define MD5_LEN       (32+1)
#define BUFFSIZE      1024
#define NROWS         11
#define MAX_FILES     3

static const char *TAG = "ETS";
static bool RUNNING       = true;
static bool ONCE          = true;
static bool WIFI_CONNECTED = false;
static bool MQTT_CONNECTED = false;
static bool WHICH_FILE    = false;
static bool FILE_CHANGED  = true;

static _lock_t lck_file;
static _lock_t lck_mqtt;

static TaskHandle_t xHandle_led   = NULL;
static TaskHandle_t xHandle_sniff = NULL;
static TaskHandle_t xHandle_wifi  = NULL;

static esp_mqtt_client_handle_t client;
static EventGroupHandle_t wifi_event_group;

typedef struct {
    int16_t  fctl;
    int16_t  duration;
    uint8_t  da[6];
    uint8_t  sa[6];
    uint8_t  bssid[6];
    int16_t  seqctl;
    unsigned char payload[];
} __attribute__((packed)) wifi_mgmt_hdr;

/* --- Forward declarations --- */
static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data);
static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data);

static void vfs_spiffs_init(void);
static void time_init(void);
static void initialize_sntp(void);
static void obtain_time(void);

static void blink_task(void *pvParameter);
static void set_blink_led(int state);

static void sniffer_task(void *pvParameter);
static void wifi_sniffer_init(void);
static void wifi_sniffer_deinit(void);
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);
static void get_hash(unsigned char *data, int len_res, char hash[MD5_LEN]);
static void get_ssid(unsigned char *data, char ssid[SSID_MAX_LEN], uint8_t ssid_len);
static int  get_sn(unsigned char *data);
static void get_ht_capabilites_info(unsigned char *data, char htci[5], int pkt_len, int ssid_len);
static void dumb(unsigned char *data, int len);
static void save_pkt_info(uint8_t address[6], char *ssid, time_t timestamp, char *hash, int8_t rssi, int sn, char htci[5]);
static int  get_start_timestamp(void);

static void wifi_task(void *pvParameter);
static void wifi_connect_init(void);
static void wifi_connect_deinit(void);
static void mqtt_app_start(void);
static int  set_waiting_time(void);
static void send_data(void);
static void file_init(char *filename);

static void reboot(char *msg_err);

/* ===================================================================
 * app_main
 * =================================================================== */
void app_main(void)
{
    ESP_LOGI(TAG, "[+] Startup...");

    /* NVS must be initialised before WiFi */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_LOGI(TAG, "[!] Starting blink task...");
    xTaskCreate(&blink_task, "blink_task", configMINIMAL_STACK_SIZE, NULL, 5, &xHandle_led);
    if (xHandle_led == NULL)
        reboot("Impossible to create LED task");

    set_blink_led(STARTUP_MODE);

    wifi_connect_init();

    if (CONFIG_VERBOSE) {
        uint8_t l_Mac[6];
        esp_wifi_get_mac(WIFI_IF_STA, l_Mac);
        ESP_LOGI(TAG, "MAC Address: %02x:%02x:%02x:%02x:%02x:%02x",
                 l_Mac[0], l_Mac[1], l_Mac[2], l_Mac[3], l_Mac[4], l_Mac[5]);

        esp_netif_ip_info_t ip_info;
        esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        if (netif != NULL) {
            esp_netif_get_ip_info(netif, &ip_info);
            ESP_LOGI(TAG, "IP Address:  " IPSTR, IP2STR(&ip_info.ip));
            ESP_LOGI(TAG, "Subnet mask: " IPSTR, IP2STR(&ip_info.netmask));
            ESP_LOGI(TAG, "Gateway:     " IPSTR, IP2STR(&ip_info.gw));
        }

        ESP_LOGI(TAG, "Free memory: %" PRIu32 " bytes", esp_get_free_heap_size());
        ESP_LOGI(TAG, "IDF version: %s", esp_get_idf_version());

        esp_log_level_set("*", ESP_LOG_INFO);
        esp_log_level_set("MQTT_CLIENT", ESP_LOG_VERBOSE);
        esp_log_level_set("TRANSPORT_TCP", ESP_LOG_VERBOSE);
        esp_log_level_set("TRANSPORT", ESP_LOG_VERBOSE);
        esp_log_level_set("OUTBOX", ESP_LOG_VERBOSE);
    }

    vfs_spiffs_init();
    time_init();

    _lock_init(&lck_file);
    _lock_init(&lck_mqtt);
    file_init(CONFIG_FILENAME1);
    file_init(CONFIG_FILENAME2);

    ESP_LOGI(TAG, "[!] Starting sniffing task...");
    xTaskCreate(&sniffer_task, "sniffer_task", 10000, NULL, 1, &xHandle_sniff);
    if (xHandle_sniff == NULL)
        reboot("Impossible to create sniffing task");

    ESP_LOGI(TAG, "[!] Starting Wi-Fi task...");
    xTaskCreate(&wifi_task, "wifi_task", 10000, NULL, 1, &xHandle_wifi);
    if (xHandle_wifi == NULL)
        reboot("Impossible to create Wi-Fi task");

    while (RUNNING) {
        vTaskDelay(500 / portTICK_PERIOD_MS);
    }

    ESP_LOGW(TAG, "Deleting tasks...");
    vTaskDelete(xHandle_led);
    vTaskDelete(xHandle_sniff);
    vTaskDelete(xHandle_wifi);

    ESP_LOGW(TAG, "Unmounting SPIFFS");
    esp_vfs_spiffs_unregister(NULL);

    ESP_LOGW(TAG, "Stopping sniffing mode...");
    wifi_sniffer_deinit();

    ESP_LOGW(TAG, "Disconnecting from %s...", CONFIG_WIFI_SSID);
    wifi_connect_deinit();

    reboot("Rebooting: Fatal error occurred in a task");
}

/* ===================================================================
 * WiFi event handler  (replaces old system_event_t callback)
 * =================================================================== */
static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                                int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        ESP_LOGI(TAG, "[WI-FI] Connecting to %s", CONFIG_WIFI_SSID);
        ESP_ERROR_CHECK(esp_wifi_connect());

    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ESP_LOGI(TAG, "[WI-FI] Connected");
        WIFI_CONNECTED = true;
        set_blink_led(ON_MODE);
        xEventGroupSetBits(wifi_event_group, BIT0);

    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGI(TAG, "[WI-FI] Disconnected");
        if (WIFI_CONNECTED == false)
            ESP_LOGW(TAG, "[WI-FI] Impossible to connect: wrong password/SSID or Wi-Fi down");
        WIFI_CONNECTED = false;
        set_blink_led(OFF_MODE);
        if (RUNNING)
            esp_wifi_connect();
        else
            xEventGroupClearBits(wifi_event_group, BIT0);
    }
}

/* ===================================================================
 * MQTT event handler  (new signature for IDF 5.x)
 * =================================================================== */
static void mqtt_event_handler(void *handler_args, esp_event_base_t base,
                                int32_t event_id, void *event_data)
{
    esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;
    client = event->client;

    switch ((esp_mqtt_event_id_t)event_id) {
        case MQTT_EVENT_CONNECTED:
            ESP_LOGI(TAG, "[MQTT] Connected");
            _lock_acquire(&lck_mqtt);
            MQTT_CONNECTED = true;
            _lock_release(&lck_mqtt);
            set_blink_led(BLINK_MODE);
            break;

        case MQTT_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "[MQTT] Disconnected");
            _lock_acquire(&lck_mqtt);
            MQTT_CONNECTED = false;
            _lock_release(&lck_mqtt);
            set_blink_led(ON_MODE);
            break;

        case MQTT_EVENT_PUBLISHED:
            ESP_LOGI(TAG, "[MQTT] EVENT_PUBLISHED, msg_id=%d", event->msg_id);
            break;

        case MQTT_EVENT_ERROR:
            ESP_LOGI(TAG, "[MQTT] MQTT_EVENT_ERROR");
            break;

        default:
            break;
    }
}

/* ===================================================================
 * LED
 * =================================================================== */
static void blink_task(void *pvParameter)
{
    gpio_reset_pin(BLINK_GPIO);
    gpio_set_direction(BLINK_GPIO, GPIO_MODE_OUTPUT);

    while (true) {
        gpio_set_level(BLINK_GPIO, 0);
        vTaskDelay(BLINK_TIME_OFF / portTICK_PERIOD_MS);
        gpio_set_level(BLINK_GPIO, 1);
        vTaskDelay(BLINK_TIME_ON / portTICK_PERIOD_MS);
    }
}

static void set_blink_led(int state)
{
    switch (state) {
        case BLINK_MODE:   BLINK_TIME_OFF = 1000; BLINK_TIME_ON = 1000; break;
        case ON_MODE:      BLINK_TIME_OFF = 5;    BLINK_TIME_ON = 2000; break;
        case OFF_MODE:     BLINK_TIME_OFF = 2000; BLINK_TIME_ON = 5;    break;
        case STARTUP_MODE: BLINK_TIME_OFF = 100;  BLINK_TIME_ON = 100;  break;
        default: break;
    }
}

/* ===================================================================
 * SPIFFS
 * =================================================================== */
static void vfs_spiffs_init()
{
    esp_vfs_spiffs_conf_t conf = {
        .base_path             = "/spiffs",
        .partition_label       = NULL,
        .max_files             = MAX_FILES,
        .format_if_mount_failed = true
    };

    esp_err_t ret = esp_vfs_spiffs_register(&conf);

    if (ret != ESP_OK) {
        if (ret == ESP_FAIL)
            ESP_LOGE(TAG, "Failed to mount or format filesystem");
        else if (ret == ESP_ERR_NOT_FOUND)
            ESP_LOGE(TAG, "Failed to find SPIFFS partition");
        else
            ESP_LOGE(TAG, "Failed to initialize SPIFFS (%s)", esp_err_to_name(ret));
        reboot("Fatal error SPIFFS");
    }

    size_t total = 0, used = 0;
    ret = esp_spiffs_info(NULL, &total, &used);
    if (ret != ESP_OK)
        ESP_LOGE(TAG, "Failed to get SPIFFS partition info (%s)", esp_err_to_name(ret));
    else
        ESP_LOGI(TAG, "[SPIFFS] Partition size: total: %d, used: %d", total, used);
}

/* ===================================================================
 * Time / NTP
 * =================================================================== */
static void time_init()
{
    time_t now;
    struct tm timeinfo;
    char strftime_buf[64];

    ESP_LOGI(TAG, "Connecting to WiFi and getting time over NTP.");
    obtain_time();
    time(&now);

    setenv("TZ", "GMT0BST,M3.5.0/1,M10.5.0", 1);
    tzset();
    localtime_r(&now, &timeinfo);
    strftime(strftime_buf, sizeof(strftime_buf), "%c", &timeinfo);
    ESP_LOGI(TAG, "TIME INFO: The Greenwich date/time is: %s", strftime_buf);
}

static void obtain_time()
{
    time_t now = 0;
    struct tm timeinfo = { 0 };
    int retry = 0;
    const int retry_count = 15;

    initialize_sntp();

    while (timeinfo.tm_year < (2016 - 1900) && ++retry < retry_count) {
        ESP_LOGI(TAG, "Waiting for system time to be set... (%d/%d)", retry, retry_count);
        vTaskDelay(2000 / portTICK_PERIOD_MS);
        time(&now);
        localtime_r(&now, &timeinfo);
    }

    if (retry >= retry_count) {
        if (ONCE)
            reboot("No response from NTP server. Impossible to set current time");
    } else {
        ONCE = false;
    }
}

static void initialize_sntp()
{
    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, "pool.ntp.org");
    esp_sntp_init();
}

/* ===================================================================
 * File helpers
 * =================================================================== */
static void file_init(char *filename)
{
    FILE *fp = fopen(filename, "wb");
    if (fp == NULL) {
        RUNNING = false;
        ESP_LOGE(TAG, "Error creating or initializing file %s", filename);
        return;
    }
    ESP_LOGI(TAG, "File %s initialized", filename);
    fclose(fp);
}

/* ===================================================================
 * WiFi connect / disconnect
 * =================================================================== */
static void wifi_connect_init()
{
    esp_log_level_set("wifi", ESP_LOG_NONE);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_event_group = xEventGroupCreate();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, NULL));

    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid     = CONFIG_WIFI_SSID,
            .password = CONFIG_WIFI_PSW,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Waiting for connection to the WiFi network...");
    xEventGroupWaitBits(wifi_event_group, BIT0, false, true, portMAX_DELAY);
}

static void wifi_connect_deinit()
{
    ESP_ERROR_CHECK(esp_wifi_disconnect());
    ESP_ERROR_CHECK(esp_wifi_stop());
    ESP_ERROR_CHECK(esp_wifi_deinit());
}

/* ===================================================================
 * MQTT
 * =================================================================== */
static void mqtt_app_start()
{
    const esp_mqtt_client_config_t mqtt_cfg = {
        .broker.address.uri    = "mqtt://broker.hivemq.com",
        .credentials.client_id = CONFIG_ESP32_ID,
        .session.keepalive     = 120,
        .buffer.size           = BUFFSIZE,
    };

    client = esp_mqtt_client_init(&mqtt_cfg);
    esp_mqtt_client_register_event(client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
    esp_mqtt_client_start(client);

    ESP_LOGI(TAG, "[MQTT] Connecting to %s:%d", CONFIG_BROKER_ADDR, CONFIG_BROKER_PORT);
}

/* ===================================================================
 * WiFi task — waits for publish interval then sends data
 * =================================================================== */
static void wifi_task(void *pvParameter)
{
    ESP_LOGI(TAG, "[WIFI] Wi-Fi task created");
    mqtt_app_start();

    while (true) {
        vTaskDelay(set_waiting_time() / portTICK_PERIOD_MS);

        _lock_acquire(&lck_mqtt);
        if (MQTT_CONNECTED)
            send_data();
        else
            ESP_LOGW(TAG, "[WI-FI] Not connected to broker, skipping publish");
        _lock_release(&lck_mqtt);
    }
}

static int set_waiting_time()
{
    time_t t;
    time(&t);
    return (CONFIG_SNIFFING_TIME - (int)t % CONFIG_SNIFFING_TIME) * 1000;
}

static void send_data()
{
    FILE *fp = NULL;
    int msg_id, tid;
    int sending = true, reading = true, tot_read = 0, n = 1;
    char *topic, buffer[BUFFSIZE], last_pkt = 'F';
    ssize_t len = strlen(CONFIG_ETS) + strlen(CONFIG_ROOM) + strlen(CONFIG_ESP32_ID) + 3;

    _lock_acquire(&lck_file);
    if (WHICH_FILE) {
        WHICH_FILE = false;
        FILE_CHANGED = true;
        fp = fopen(CONFIG_FILENAME1, "r");
        if (fp == NULL) { RUNNING = false; ESP_LOGE(TAG, "[WI-FI] Cannot open %s", CONFIG_FILENAME1); return; }
    } else {
        WHICH_FILE = true;
        FILE_CHANGED = true;
        fp = fopen(CONFIG_FILENAME2, "r");
        if (fp == NULL) { RUNNING = false; ESP_LOGE(TAG, "[WI-FI] Cannot open %s", CONFIG_FILENAME2); return; }
    }
    _lock_release(&lck_file);

    topic = malloc(len * sizeof(char));
    memset(topic, '\0', len);
    strcpy(topic, CONFIG_ETS);
    strcat(topic, "/");
    strcat(topic, CONFIG_ROOM);
    strcat(topic, "/");
    strcat(topic, CONFIG_ESP32_ID);

    fscanf(fp, "%d", &tid);

    ESP_LOGI(TAG, "[WI-FI] Sending to %s:%d", CONFIG_BROKER_ADDR, CONFIG_BROKER_PORT);
    while (sending) {
        n = 1;
        tot_read = 0;
        memset(buffer, '\0', BUFFSIZE);
        sprintf(buffer, "%c %d\n", last_pkt, tid);
        tot_read = strlen(buffer);

        reading = true;
        while (fgets(buffer + tot_read, BUFFSIZE, fp) != NULL && reading) {
            n++;
            tot_read = strlen(buffer);
            if (n >= NROWS) reading = false;
        }

        if (reading) {
            last_pkt = 'T';
            buffer[0] = last_pkt;
            sending = false;
        }

        msg_id = esp_mqtt_client_publish(client, topic, buffer, strlen(buffer), 0, 0);
        ESP_LOGI(TAG, "[WI-FI] Sent publish on topic=%s, msg_id=%d", topic, msg_id);
    }

    _lock_acquire(&lck_file);
    if (WHICH_FILE) { fclose(fp); file_init(CONFIG_FILENAME2); }
    else             { fclose(fp); file_init(CONFIG_FILENAME1); }
    _lock_release(&lck_file);

    free(topic);
}

/* ===================================================================
 * Sniffer task — channel hopping + promiscuous capture
 * =================================================================== */
static void sniffer_task(void *pvParameter)
{
    int sleep_time      = CONFIG_SNIFFING_TIME * 1000;
    int channel         = 1;
    int hops            = 0;
    int hops_per_publish = sleep_time / 500;

    ESP_LOGI(TAG, "[SNIFFER] Sniffer task created");
    ESP_LOGI(TAG, "[SNIFFER] Starting sniffing mode...");
    wifi_sniffer_init();
    ESP_LOGI(TAG, "[SNIFFER] Started. Channel hopping 1-13");

    while (true) {
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        channel = (channel % 13) + 1;
        hops++;

        vTaskDelay(500 / portTICK_PERIOD_MS);

        if (hops >= hops_per_publish) {
            hops = 0;
            _lock_acquire(&lck_mqtt);
            if (!MQTT_CONNECTED) {
                ESP_LOGW(TAG, "[SNIFFER] Initializing file...");
                _lock_acquire(&lck_file);
                if (WHICH_FILE) file_init(CONFIG_FILENAME1);
                else            file_init(CONFIG_FILENAME2);
                _lock_release(&lck_file);
            }
            _lock_release(&lck_mqtt);
        }
    }
}

static void wifi_sniffer_init()
{
    const wifi_country_t wifi_country = {
        .cc     = "CN",
        .schan  = 1,
        .nchan  = 13,
        .policy = WIFI_COUNTRY_POLICY_AUTO
    };
    ESP_ERROR_CHECK(esp_wifi_set_country(&wifi_country));

    const wifi_promiscuous_filter_t filt = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT
    };
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filt));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_packet_handler));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
}

static void wifi_sniffer_deinit()
{
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(false));
}

static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type)
{
    int pkt_len, fc, sn = 0;
    char ssid[SSID_MAX_LEN] = "\0", hash[MD5_LEN] = "\0", htci[5] = "\0";
    uint8_t ssid_len;
    time_t ts;

    wifi_promiscuous_pkt_t *pkt  = (wifi_promiscuous_pkt_t *)buff;
    wifi_mgmt_hdr          *mgmt = (wifi_mgmt_hdr *)pkt->payload;

    fc = ntohs(mgmt->fctl);

    if ((fc & 0xFF00) == 0x4000) { // probe request
        time(&ts);

        ssid_len = pkt->payload[25];
        if (ssid_len > 0)
            get_ssid(pkt->payload, ssid, ssid_len);

        pkt_len = pkt->rx_ctrl.sig_len;
        get_hash(pkt->payload, pkt_len - 4, hash);

        if (CONFIG_VERBOSE) {
            ESP_LOGI(TAG, "Dump");
            dumb(pkt->payload, pkt_len);
        }

        sn = get_sn(pkt->payload);
        get_ht_capabilites_info(pkt->payload, htci, pkt_len, ssid_len);

        ESP_LOGI(TAG, "ADDR=%02x:%02x:%02x:%02x:%02x:%02x, SSID=%s, TIMESTAMP=%d, HASH=%s, RSSI=%02d, SN=%d, HT CAP. INFO=%s",
                 mgmt->sa[0], mgmt->sa[1], mgmt->sa[2], mgmt->sa[3], mgmt->sa[4], mgmt->sa[5],
                 ssid, (int)ts, hash, pkt->rx_ctrl.rssi, sn, htci);

        save_pkt_info(mgmt->sa, ssid, ts, hash, pkt->rx_ctrl.rssi, sn, htci);
    }
}

/* ===================================================================
 * Packet parsing helpers
 * =================================================================== */
static void get_hash(unsigned char *data, int len_res, char hash[MD5_LEN])
{
    uint8_t pkt_hash[16];
    md5((uint8_t *)data, len_res, pkt_hash);
    sprintf(hash, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            pkt_hash[0],  pkt_hash[1],  pkt_hash[2],  pkt_hash[3],
            pkt_hash[4],  pkt_hash[5],  pkt_hash[6],  pkt_hash[7],
            pkt_hash[8],  pkt_hash[9],  pkt_hash[10], pkt_hash[11],
            pkt_hash[12], pkt_hash[13], pkt_hash[14], pkt_hash[15]);
}

static void get_ssid(unsigned char *data, char ssid[SSID_MAX_LEN], uint8_t ssid_len)
{
    int i, j;
    for (i = 26, j = 0; i < 26 + ssid_len; i++, j++)
        ssid[j] = data[i];
    ssid[j] = '\0';
}

static int get_sn(unsigned char *data)
{
    int sn;
    char num[5] = "\0";
    sprintf(num, "%02x%02x", data[22], data[23]);
    sscanf(num, "%x", &sn);
    return sn;
}

static void get_ht_capabilites_info(unsigned char *data, char htci[5], int pkt_len, int ssid_len)
{
    int ht_start = 25 + ssid_len + 19;
    if (data[ht_start - 1] > 0 && ht_start < pkt_len - 4) {
        if (data[ht_start - 4] == 1)
            sprintf(htci, "%02x%02x", data[ht_start + 3],     data[ht_start + 1 + 3]);
        else
            sprintf(htci, "%02x%02x", data[ht_start],         data[ht_start + 1]);
    }
}

static void dumb(unsigned char *data, int len)
{
    unsigned char i, j, byte;
    for (i = 0; i < len; i++) {
        byte = data[i];
        printf("%02x ", data[i]);
        if (((i % 16) == 15) || (i == len - 1)) {
            for (j = 0; j < 15 - (i % 16); j++) printf(" ");
            printf("| ");
            for (j = (i - (i % 16)); j <= i; j++) {
                byte = data[j];
                if ((byte > 31) && (byte < 127)) printf("%c", byte);
                else printf(".");
            }
            printf("\n");
        }
    }
}

static void save_pkt_info(uint8_t address[6], char *ssid, time_t timestamp,
                           char *hash, int8_t rssi, int sn, char htci[5])
{
    FILE *fp = NULL;
    int stime;

    _lock_acquire(&lck_file);
    if (WHICH_FILE) fp = fopen(CONFIG_FILENAME1, "a");
    else            fp = fopen(CONFIG_FILENAME2, "a");
    _lock_release(&lck_file);

    if (fp == NULL) {
        ESP_LOGE(TAG, "[SNIFFER] Cannot open file to save packet info");
        return;
    }

    if (FILE_CHANGED) {
        FILE_CHANGED = false;
        stime = get_start_timestamp();
        fprintf(fp, "%d\n", stime);
    }

    fprintf(fp, "%02x:%02x:%02x:%02x:%02x:%02x %s %d %s %02d %d %s\n",
            address[0], address[1], address[2], address[3], address[4], address[5],
            ssid, (int)timestamp, hash, rssi, sn, htci);

    fclose(fp);
}

static int get_start_timestamp()
{
    time_t clk;
    time(&clk);
    return (int)clk - (int)clk % CONFIG_SNIFFING_TIME;
}

/* ===================================================================
 * Reboot
 * =================================================================== */
static void reboot(char *msg_err)
{
    ESP_LOGE(TAG, "%s", msg_err);
    for (int i = 3; i >= 0; i--) {
        ESP_LOGW(TAG, "Restarting in %d seconds...", i);
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
    ESP_LOGW(TAG, "Restarting now");
    fflush(stdout);
    esp_restart();
}
