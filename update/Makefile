CC ?= cc
CPPFLAGS += -Iinclude $(shell pkg-config --cflags openssl)
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Werror -Wpedantic
LDLIBS += $(shell pkg-config --libs openssl)
BUILD ?= ../build/update
.PHONY: check check-manifest clean
check: check-manifest
check-manifest: $(BUILD)/test_manifest
	$(BUILD)/test_manifest
$(BUILD)/test_manifest: tests/test_manifest.c src/manifest.c include/d2k_update.h
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_manifest.c src/manifest.c $(LDFLAGS) $(LDLIBS) -o $@
clean:
	rm -f $(BUILD)/test_manifest
