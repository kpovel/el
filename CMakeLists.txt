cmake_minimum_required(VERSION 3.13)

set(PICO_BOARD pico2_w)
set(PICO_SDK_FETCH_FROM_GIT on)
set(PICO_SDK_FETCH_FROM_GIT_TAG "2.2.0")
include(pico_sdk_import.cmake)

project(grid_monitor C CXX ASM)
set(CMAKE_C_STANDARD 11)
pico_sdk_init()

# Fetch micro-ecc v1.0 source for secp160r1 multi-curve API.
# btstack bundles an older single-curve micro-ecc; src/ecdh.c includes
# the v1.0 source with renamed symbols to avoid clashes.
include(FetchContent)
FetchContent_Declare(micro_ecc
    GIT_REPOSITORY https://github.com/kmackay/micro-ecc.git
    GIT_TAG        v1.0)
FetchContent_MakeAvailable(micro_ecc)

add_executable(grid_monitor
    src/main.c src/ble.c src/crypto.c src/ecdh.c
    src/protocol.c src/keydata.c)

target_include_directories(grid_monitor PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${micro_ecc_SOURCE_DIR})

target_compile_definitions(grid_monitor PRIVATE
    ECOFLOW_ADDRESS="${ECOFLOW_ADDRESS}"
    ECOFLOW_SERIAL="${ECOFLOW_SERIAL}"
    ECOFLOW_USER_ID="${ECOFLOW_USER_ID}"
    uECC_SUPPORTS_secp160r1=1
    uECC_OPTIMIZATION_LEVEL=3)

target_link_libraries(grid_monitor
    pico_stdlib
    pico_cyw43_arch_none
    pico_btstack_ble
    pico_btstack_cyw43
    pico_mbedtls)

pico_enable_stdio_usb(grid_monitor 1)
pico_enable_stdio_uart(grid_monitor 0)
pico_add_extra_outputs(grid_monitor)
