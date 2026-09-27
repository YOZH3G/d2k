CC ?= cc
ZIG ?= /opt/homebrew/bin/zig
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L
VERSION ?= dev
COMMIT ?=
BUILT ?=
DIRTY ?= 0

.PHONY: all test test-js test-cli san clean d2kpanel-linux-arm64

all: d2kpanel

d2kpanel: main.c server.h server.c
	$(CC) $(CFLAGS) -o $@ main.c server.c

d2kpanel-linux-arm64: main.c server.h server.c
	mkdir -p ../builds
	$(ZIG) cc -target aarch64-linux-musl -static -Os -std=c11 -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200809L -DD2K_PANEL_VERSION='"$(VERSION)"' \
		-DD2K_PANEL_COMMIT='"$(COMMIT)"' -DD2K_PANEL_BUILT='"$(BUILT)"' \
		-DD2K_PANEL_DIRTY=$(DIRTY) -o ../builds/d2kpanel-linux-arm64 main.c server.c

test_server: test_server.c server.h server.c
	$(CC) $(CFLAGS) -pthread -o $@ test_server.c server.c

test_server_san: test_server.c server.h server.c
	$(CC) $(CFLAGS) -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
		-pthread -o $@ test_server.c server.c

san: test_server_san
	ASAN_OPTIONS=detect_leaks=0 ./test_server_san

test-js:
	node test_ui.cjs

test-cli: d2kpanel
	node test_cli.cjs

test: test_server d2kpanel test-js
	./test_server
	node test_cli.cjs

clean:
	rm -f test_server test_server_san d2kpanel
