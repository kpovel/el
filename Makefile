ADDRESS ?=
SERIAL  ?=
USER_ID ?=

all: build

build:
	@test -n "$(ADDRESS)" || { echo "Set ADDRESS"; exit 1; }
	@test -n "$(SERIAL)"  || { echo "Set SERIAL"; exit 1; }
	@test -n "$(USER_ID)" || { echo "Set USER_ID"; exit 1; }
	cmake -B build \
	  -DECOFLOW_ADDRESS="$(ADDRESS)" \
	  -DECOFLOW_SERIAL="$(SERIAL)"   \
	  -DECOFLOW_USER_ID="$(USER_ID)"
	@# Patch btstack hci.c: le_advertisements_state renamed to le_advertisements_todo in SDK 2.2.0
	@sed -i 's/le_advertisements_state/le_advertisements_todo/g' \
	  build/_deps/pico_sdk-src/lib/btstack/src/hci.c 2>/dev/null || true
	cmake --build build -j$$(nproc)

flash: build
	./flash.sh

clean:
	rm -rf build

.PHONY: all build flash clean
