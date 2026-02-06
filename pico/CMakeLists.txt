cmake_minimum_required(VERSION 3.13)

set(PICO_BOARD pico2_w)
set(PICO_SDK_FETCH_FROM_GIT on)
set(PICO_SDK_FETCH_FROM_GIT_TAG "2.2.0")

include(pico_sdk_import.cmake)

project(grid_monitor C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

pico_sdk_init()

set(WIFI_SSID "" CACHE STRING "WiFi network name")
set(WIFI_PASSWORD "" CACHE STRING "WiFi password")
set(SERVER_IP "192.168.1.91" CACHE STRING "Grid status server IP address")
set(SERVER_PORT 6969 CACHE STRING "Grid status server port")

if(WIFI_SSID STREQUAL "")
    message(FATAL_ERROR "WIFI_SSID is required. Pass -DWIFI_SSID=\"your_ssid\"")
endif()
if(WIFI_PASSWORD STREQUAL "")
    message(FATAL_ERROR "WIFI_PASSWORD is required. Pass -DWIFI_PASSWORD=\"your_password\"")
endif()

add_executable(grid_monitor main.c)

target_compile_definitions(grid_monitor PRIVATE
    WIFI_SSID="${WIFI_SSID}"
    WIFI_PASSWORD="${WIFI_PASSWORD}"
    SERVER_IP="${SERVER_IP}"
    SERVER_PORT=${SERVER_PORT}
)

target_include_directories(grid_monitor PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(grid_monitor
    pico_stdlib
    pico_cyw43_arch_lwip_threadsafe_background
)

pico_enable_stdio_usb(grid_monitor 1)
pico_enable_stdio_uart(grid_monitor 0)

pico_add_extra_outputs(grid_monitor)
