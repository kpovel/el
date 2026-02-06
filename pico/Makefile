BUILD_DIR   := build
UF2         := $(BUILD_DIR)/grid_monitor.uf2
PICO_VOLUME := RP2350
MOUNT_BASE  := /run/media/$(shell whoami)
MOUNT_POINT := $(MOUNT_BASE)/$(PICO_VOLUME)

WIFI_SSID     ?=
WIFI_PASSWORD ?=
SERVER_IP     ?= 192.168.1.100
SERVER_PORT   ?= 6969
JOBS          ?= $(shell nproc)

CMAKE_ARGS := -DWIFI_SSID="$(WIFI_SSID)" \
              -DWIFI_PASSWORD="$(WIFI_PASSWORD)" \
              -DSERVER_IP="$(SERVER_IP)" \
              -DSERVER_PORT=$(SERVER_PORT)

.PHONY: all build configure flash mount unmount clean

all: build

configure: | $(BUILD_DIR)
	cmake -S . -B $(BUILD_DIR) $(CMAKE_ARGS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

build: configure
	$(MAKE) -C $(BUILD_DIR) -j$(JOBS)

mount:
	@if mountpoint -q $(MOUNT_POINT) 2>/dev/null; then \
		echo "$(PICO_VOLUME) already mounted at $(MOUNT_POINT)"; \
	else \
		echo "Waiting for $(PICO_VOLUME) device (hold BOOTSEL and plug in)..."; \
		while [ ! -b /dev/disk/by-label/$(PICO_VOLUME) ]; do sleep 0.5; done; \
		udisksctl mount -b /dev/disk/by-label/$(PICO_VOLUME) --no-user-interaction; \
	fi

unmount:
	@if mountpoint -q $(MOUNT_POINT) 2>/dev/null; then \
		sync; \
		udisksctl unmount -b /dev/disk/by-label/$(PICO_VOLUME) --no-user-interaction; \
	fi

flash: build mount
	@test -f $(UF2) || { echo "Error: $(UF2) not found"; exit 1; }
	@echo "Flashing $(UF2) -> $(MOUNT_POINT)"
	cp $(UF2) $(MOUNT_POINT)/
	@echo "Done — Pico will reboot automatically"

clean:
	rm -rf $(BUILD_DIR)
