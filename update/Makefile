CC ?= cc
CPPFLAGS += -Iinclude $(shell pkg-config --cflags openssl)
CFLAGS ?= -O2 -g
CFLAGS += -UNDEBUG -std=c11 -Wall -Wextra -Werror -Wpedantic
LDLIBS += $(shell pkg-config --libs openssl)
BUILD ?= ../build/update
.PHONY: check check-manifest clean
check: check-manifest check-transport check-package check-schedule
check-manifest: $(BUILD)/test_manifest
	$(BUILD)/test_manifest
$(BUILD)/test_manifest: tests/test_manifest.c src/manifest.c include/d2k_update.h
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_manifest.c src/manifest.c $(LDFLAGS) $(LDLIBS) -o $@
clean:
	rm -f $(BUILD)/test_manifest $(BUILD)/test_transport $(BUILD)/test_package $(BUILD)/test_schedule

.PHONY: check-schedule
check-schedule: $(BUILD)/test_schedule
	$(BUILD)/test_schedule
$(BUILD)/test_schedule: tests/test_schedule.c src/schedule.c include/d2k_update.h
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_schedule.c src/schedule.c $(LDFLAGS) -o $@

.PHONY: check-transport check-package
CURL_CFLAGS ?= $(shell pkg-config --cflags libcurl)
CURL_LIBS ?= $(shell pkg-config --libs libcurl)
check-transport: $(BUILD)/test_transport
	python3 tests/run_transport.py $(BUILD)/test_transport
check-package: $(BUILD)/test_package
	$(BUILD)/test_package
$(BUILD)/test_transport: tests/test_transport.c src/transport.c src/manifest.c include/d2k_update.h
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CURL_CFLAGS) $(CFLAGS) tests/test_transport.c src/transport.c src/manifest.c $(LDFLAGS) $(CURL_LIBS) $(LDLIBS) -o $@
$(BUILD)/test_package: tests/test_package.c src/package.c include/d2k_update.h
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_package.c src/package.c $(LDFLAGS) $(LDLIBS) -o $@
