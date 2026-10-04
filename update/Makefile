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
	rm -f $(BUILD)/test_manifest $(BUILD)/test_transport $(BUILD)/test_package $(BUILD)/test_schedule $(BUILD)/test_journal $(BUILD)/test_health $(BUILD)/test_health_local $(BUILD)/test_health_fifo $(BUILD)/test_runtime_signal $(BUILD)/test_transaction $(BUILD)/test_recovery $(BUILD)/d2k-update-boot

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

.PHONY: check-journal
check: check-journal
check-journal: $(BUILD)/test_journal
	$(BUILD)/test_journal
$(BUILD)/test_journal: tests/test_journal.c src/journal.c include/d2k_update.h
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_journal.c src/journal.c $(LDFLAGS) $(LDLIBS) -o $@

.PHONY: check-health
check: check-health
check-health: $(BUILD)/test_health $(BUILD)/test_health_local
	$(BUILD)/test_health
	$(BUILD)/test_health_local
$(BUILD)/test_health: tests/test_health.c src/health.c include/d2k_update.h ../runtime/d2k_runtime.h
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_health.c src/health.c $(LDFLAGS) -o $@
$(BUILD)/test_health_local: tests/test_health_local.c src/health.c include/d2k_update.h ../runtime/d2k_runtime.h
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_health_local.c src/health.c $(LDFLAGS) -o $@

.PHONY: check-health-fifo
check-health: check-health-fifo
check-health-fifo: $(BUILD)/test_health_fifo
	$(BUILD)/test_health_fifo
$(BUILD)/test_health_fifo: tests/test_health_fifo.c src/health.c include/d2k_update.h ../runtime/d2k_runtime.h
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_health_fifo.c src/health.c $(LDFLAGS) -o $@

.PHONY: check-runtime-signal
# Linux only; isolated fixture paths supplied by the runtime smoke harness.
check-runtime-signal: $(BUILD)/test_runtime_signal
	$(BUILD)/test_runtime_signal "$(SIGNAL_BINARY)" "$(SIGNAL_CONFIG)" "$(SIGNAL_HEALTH)" "$(SIGNAL_LOG)" "$(SIGNAL_STATUS)"
$(BUILD)/test_runtime_signal: tests/test_runtime_signal_linux.c ../runtime/d2k_runtime.h
	mkdir -p $(BUILD)
	$(CC) $(CFLAGS) tests/test_runtime_signal_linux.c $(LDFLAGS) -o $@

TRANSACTION_SRC = src/transaction.c src/recover.c src/journal.c src/package.c src/health.c src/schedule.c
.PHONY: check-transaction check-recovery boot
check: check-transaction check-recovery
check-transaction: $(BUILD)/test_transaction
	$(BUILD)/test_transaction
check-recovery: $(BUILD)/test_recovery
	$(BUILD)/test_recovery
$(BUILD)/test_transaction: tests/test_transaction.c tests/transaction_fixture.h $(TRANSACTION_SRC) include/d2k_update.h src/transaction_internal.h
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_transaction.c $(TRANSACTION_SRC) $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/test_recovery: tests/test_recovery.c tests/transaction_fixture.h $(TRANSACTION_SRC) include/d2k_update.h src/transaction_internal.h
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_recovery.c $(TRANSACTION_SRC) $(LDFLAGS) $(LDLIBS) -o $@
boot: $(BUILD)/d2k-update-boot
$(BUILD)/d2k-update-boot: src/boot_main.c $(TRANSACTION_SRC) include/d2k_update.h src/transaction_internal.h
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) src/boot_main.c $(TRANSACTION_SRC) $(LDFLAGS) $(LDLIBS) -o $@
