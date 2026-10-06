CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Werror -pedantic
RELEASE_ID ?= dev
CPPFLAGS += -Iinclude -DD2K_RELEASE_ID='"$(RELEASE_ID)"'
BUILD_DIR ?= build
OPENSSL_CFLAGS ?= $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS ?= $(shell pkg-config --libs openssl 2>/dev/null || echo -lssl -lcrypto)

.PHONY: test test-wire test-relay test-tls test-session test-streams test-config clean arm64 d2ktg

test: test-wire test-relay test-tls test-session test-streams test-config test-enroll

test-enroll: $(BUILD_DIR)/test-enroll
	./$(BUILD_DIR)/test-enroll

$(BUILD_DIR)/test-enroll: test_enroll.c src/enroll.c src/identity.c include/tg_enroll.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(OPENSSL_CFLAGS) $(CFLAGS) -o $@ test_enroll.c src/enroll.c src/identity.c $(OPENSSL_LIBS)

test-wire: $(BUILD_DIR)/test-wire
	./$(BUILD_DIR)/test-wire

test-relay: $(BUILD_DIR)/test-relay
	./$(BUILD_DIR)/test-relay

test-tls: $(BUILD_DIR)/test-tls
	./$(BUILD_DIR)/test-tls

test-session: $(BUILD_DIR)/test-session
	./$(BUILD_DIR)/test-session

test-streams: $(BUILD_DIR)/test-streams
	./$(BUILD_DIR)/test-streams

test-config: $(BUILD_DIR)/test-config
	./$(BUILD_DIR)/test-config

d2ktg: $(BUILD_DIR)/d2ktg

$(BUILD_DIR)/d2ktg: ../runtime/d2k_runtime.h src/main.c src/config.c src/tls.c src/ws.c src/ws_pump.c src/identity.c src/register.c src/enroll.c src/net.c src/wire.c src/tunnel.c src/listener.c src/streams.c src/queue.c src/session.c
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(OPENSSL_CFLAGS) $(CFLAGS) -pthread -o $@ $(filter %.c,$^) $(OPENSSL_LIBS)

$(BUILD_DIR)/test-wire: test_wire.c src/wire.c include/tg_wire.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ test_wire.c src/wire.c

$(BUILD_DIR)/test-relay: test_relay.c src/ws.c src/identity.c src/net.c include/tg_ws.h include/tg_identity.h include/tg_net.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(OPENSSL_CFLAGS) $(CFLAGS) -o $@ test_relay.c src/ws.c src/identity.c src/net.c $(OPENSSL_LIBS)


$(BUILD_DIR)/test-tls: test_tls.c ../files/tg-roots.pem src/tls.c src/ws.c src/ws_pump.c src/identity.c src/register.c src/enroll.c src/net.c src/wire.c src/tunnel.c src/listener.c src/streams.c src/queue.c src/session.c include/tg_tls.h include/tg_ws.h include/tg_register.h include/tg_identity.h include/tg_net.h include/tg_tunnel.h include/tg_streams.h include/tg_listener.h include/tg_session.h include/tg_wire.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(OPENSSL_CFLAGS) $(CFLAGS) -pthread -o $@ test_tls.c src/tls.c src/ws.c src/ws_pump.c src/identity.c src/register.c src/enroll.c src/net.c src/wire.c src/tunnel.c src/listener.c src/streams.c src/queue.c src/session.c $(OPENSSL_LIBS)

$(BUILD_DIR)/test-session: test_session.c src/session.c src/wire.c src/identity.c include/tg_session.h include/tg_wire.h include/tg_identity.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(OPENSSL_CFLAGS) $(CFLAGS) -o $@ test_session.c src/session.c src/wire.c src/identity.c $(OPENSSL_LIBS)

$(BUILD_DIR)/test-streams: test_streams.c src/listener.c src/streams.c src/queue.c include/tg_listener.h include/tg_streams.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ test_streams.c src/listener.c src/streams.c src/queue.c

$(BUILD_DIR)/test-config: test_config.c src/config.c include/tg_config.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(OPENSSL_CFLAGS) $(CFLAGS) -o $@ test_config.c src/config.c $(OPENSSL_LIBS)

arm64:
	../scripts/build-openssl-tg.sh

clean:
	rm -rf $(BUILD_DIR)

.PHONY: test-identity
test: test-identity
test-identity: $(BUILD_DIR)/test-identity
	./$(BUILD_DIR)/test-identity
$(BUILD_DIR)/test-identity: test_identity.c src/identity.c include/tg_identity.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(OPENSSL_CFLAGS) $(CFLAGS) -o $@ test_identity.c src/identity.c $(OPENSSL_LIBS)
