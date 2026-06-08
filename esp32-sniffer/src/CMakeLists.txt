idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES
        esp-mqtt
        esp_wifi
        nvs_flash
        esp_netif
        esp_event
        spiffs
        driver
        lwip
        freertos
        log
        heap
)
