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
	rm -f $(BUILD)/test_manifest $(BUILD)/test_transport $(BUILD)/test_package $(BUILD)/test_schedule $(BUILD)/test_journal $(BUILD)/test_health $(BUILD)/test_health_local $(BUILD)/test_health_fifo $(BUILD)/test_runtime_signal $(BUILD)/test_transaction $(BUILD)/test_recovery $(BUILD)/d2k-update-boot $(BUILD)/test_offline_ownership

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

TRANSACTION_SRC = src/auto.c src/transaction.c src/recover.c src/journal.c src/package.c src/health.c src/schedule.c
.PHONY: check-transaction check-recovery boot
check: check-transaction check-recovery
check-transaction: $(BUILD)/test_transaction
	$(BUILD)/test_transaction
check-recovery: $(BUILD)/test_recovery $(BUILD)/test_offline_ownership
	$(BUILD)/test_recovery
	$(BUILD)/test_offline_ownership
$(BUILD)/test_transaction: tests/test_transaction.c tests/transaction_fixture.h $(TRANSACTION_SRC) include/d2k_update.h src/transaction_internal.h
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_transaction.c $(TRANSACTION_SRC) $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/test_recovery: tests/test_recovery.c tests/transaction_fixture.h $(TRANSACTION_SRC) include/d2k_update.h src/transaction_internal.h
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_recovery.c $(TRANSACTION_SRC) $(LDFLAGS) $(LDLIBS) -o $@
boot: $(BUILD)/d2k-update-boot
$(BUILD)/d2k-update-boot: src/boot_main.c src/lifecycle.c src/ipc.c src/service_adapter.c src/bootstrap.c $(TRANSACTION_SRC) include/d2k_update.h src/transaction_internal.h
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) src/boot_main.c src/lifecycle.c src/ipc.c src/service_adapter.c src/bootstrap.c $(TRANSACTION_SRC) $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/test_offline_ownership: tests/test_offline_ownership.c tests/transaction_fixture.h $(TRANSACTION_SRC) include/d2k_update.h src/transaction_internal.h
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_offline_ownership.c $(TRANSACTION_SRC) $(LDFLAGS) $(LDLIBS) -o $@

.PHONY: check-bootstrap service-adapter
check-bootstrap: $(BUILD)/test_service_adapter
service-adapter: $(BUILD)/d2k-service-adapter
$(BUILD)/test_service_adapter: tests/test_service_adapter.c src/service_adapter.c $(TRANSACTION_SRC) include/d2k_update.h
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_service_adapter.c src/service_adapter.c $(TRANSACTION_SRC) $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/d2k-service-adapter: src/service_main.c src/lifecycle.c src/ipc.c src/service_adapter.c src/bootstrap.c $(TRANSACTION_SRC) include/d2k_update.h
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) src/service_main.c src/lifecycle.c src/ipc.c src/service_adapter.c src/bootstrap.c $(TRANSACTION_SRC) $(LDFLAGS) $(LDLIBS) -o $@
check: check-bootstrap
check-bootstrap: $(BUILD)/test_bootstrap $(BUILD)/d2k-service-adapter $(BUILD)/d2k-update-boot
	$(BUILD)/test_service_adapter
	$(BUILD)/test_bootstrap
	python3 tests/test_managed.py $(BUILD)/d2k-service-adapter
	python3 tests/test_bootstrap_cli.py $(BUILD)/d2k-update-boot $(BUILD)/d2k-service-adapter
$(BUILD)/test_bootstrap: tests/test_bootstrap.c src/bootstrap.c $(TRANSACTION_SRC) include/d2k_update.h
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_bootstrap.c src/bootstrap.c $(TRANSACTION_SRC) $(LDFLAGS) $(LDLIBS) -o $@

.PHONY: check-ipc
check-ipc: $(BUILD)/test_ipc $(BUILD)/test_daemon
	$(BUILD)/test_ipc
	$(BUILD)/test_daemon
$(BUILD)/test_ipc: tests/test_ipc.c src/ipc.c include/d2k_update_ipc.h
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -pthread tests/test_ipc.c src/ipc.c -o $@
check: check-ipc
DAEMON_SRC = src/daemon.c src/daemon_status.c src/feed.c
$(BUILD)/test_daemon: tests/test_daemon.c $(DAEMON_SRC) src/transport.c src/manifest.c $(TRANSACTION_SRC)
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CURL_CFLAGS) $(CFLAGS) -pthread tests/test_daemon.c $(DAEMON_SRC) src/transport.c src/manifest.c $(TRANSACTION_SRC) $(LDFLAGS) $(LDLIBS) $(CURL_LIBS) -o $@

.PHONY: check-platform
check-platform: $(BUILD)/test_platform
	$(BUILD)/test_platform
$(BUILD)/test_platform: tests/test_platform.c src/platform.c src/service_adapter.c $(TRANSACTION_SRC)
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -pthread tests/test_platform.c src/platform.c src/service_adapter.c $(TRANSACTION_SRC) $(LDLIBS) -o $@
check-ipc: check-platform
.PHONY: check-feed
check-feed: $(BUILD)/test_feed
	python3 tests/run_feed.py $(BUILD)/test_feed
$(BUILD)/test_feed: tests/test_feed.c $(DAEMON_SRC) src/platform.c src/service_adapter.c src/transport.c src/manifest.c $(TRANSACTION_SRC)
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CURL_CFLAGS) $(CFLAGS) -pthread tests/test_feed.c $(DAEMON_SRC) src/platform.c src/service_adapter.c src/transport.c src/manifest.c $(TRANSACTION_SRC) $(LDLIBS) $(CURL_LIBS) -o $@
.PHONY: daemon check-daemon-cli
daemon: $(BUILD)/d2k-update
$(BUILD)/d2k-update: src/main.c src/lifecycle.c $(DAEMON_SRC) src/platform.c src/ipc.c src/service_adapter.c src/transport.c src/manifest.c $(TRANSACTION_SRC)
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CURL_CFLAGS) $(CFLAGS) -DD2K_RELEASE_ID='"$(or $(RELEASE_ID),dev)"' -pthread src/main.c src/lifecycle.c $(DAEMON_SRC) src/platform.c src/ipc.c src/service_adapter.c src/transport.c src/manifest.c $(TRANSACTION_SRC) $(LDLIBS) $(CURL_LIBS) -o $@
check-daemon-cli: daemon
	python3 tests/test_daemon_cli.py $(BUILD)/d2k-update
check-ipc: check-daemon-cli
.PHONY: check-lifecycle
check-lifecycle: $(BUILD)/test_lifecycle
	$(BUILD)/test_lifecycle
$(BUILD)/test_lifecycle: tests/test_lifecycle.c src/lifecycle.c src/ipc.c src/service_adapter.c $(TRANSACTION_SRC)
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -pthread tests/test_lifecycle.c src/lifecycle.c src/ipc.c src/service_adapter.c $(TRANSACTION_SRC) $(LDLIBS) -o $@

.PHONY: check-auto
check-auto: $(BUILD)/test_auto
	$(BUILD)/test_auto
$(BUILD)/test_auto: tests/test_auto.c $(TRANSACTION_SRC)
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_auto.c $(TRANSACTION_SRC) $(LDLIBS) -o $@

$(BUILD)/test_daemon $(BUILD)/test_feed $(BUILD)/test_platform $(BUILD)/d2k-update: include/d2k_update.h include/d2k_update_ipc.h src/daemon.h
check: check-feed check-lifecycle check-auto
.PHONY: check-supervised
check-supervised: daemon boot service-adapter
	python3 tests/test_supervised.py $(BUILD)/d2k-update $(BUILD)/d2k-update-boot $(BUILD)/d2k-service-adapter

check-ipc: check-daemon-replay
.PHONY: check-daemon-replay
check-daemon-replay: $(BUILD)/test_daemon_replay
	$(BUILD)/test_daemon_replay
$(BUILD)/test_daemon_replay: tests/test_daemon_replay.c tests/transaction_fixture.h $(DAEMON_SRC) src/transport.c src/manifest.c $(TRANSACTION_SRC) include/d2k_update.h src/daemon.h
	mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CURL_CFLAGS) $(CFLAGS) -pthread tests/test_daemon_replay.c $(DAEMON_SRC) src/transport.c src/manifest.c $(TRANSACTION_SRC) $(LDFLAGS) $(LDLIBS) $(CURL_LIBS) -o $@
