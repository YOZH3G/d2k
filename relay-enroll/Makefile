CC ?= cc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Werror -pedantic
OPENSSL_CFLAGS ?= $(shell pkg-config --cflags openssl)
OPENSSL_LIBS ?= $(shell pkg-config --libs openssl)
SOURCES = ../telegram/src/identity.c ../telegram/src/net.c
OUT = ../build/relay-enroll

.PHONY: all test
all: $(OUT)/d2k-enroll
$(OUT)/d2k-enroll: main.c $(SOURCES)
	mkdir -p $(OUT)
	$(CC) $(CFLAGS) -I../telegram/include $(OPENSSL_CFLAGS) -o $@ main.c $(SOURCES) $(OPENSSL_LIBS)

test: $(OUT)/test-enroll-server
	$(OUT)/test-enroll-server
$(OUT)/test-enroll-server: test.c main.c $(SOURCES) ../telegram/src/enroll.c
	mkdir -p $(OUT)
	$(CC) $(CFLAGS) -I../telegram/include $(OPENSSL_CFLAGS) -o $@ test.c $(SOURCES) ../telegram/src/enroll.c $(OPENSSL_LIBS)
