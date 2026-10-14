CC ?= cc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Werror -pedantic
OUT = ../build/relay-gate
ZIG ?= zig

.PHONY: all test vps
all: $(OUT)/d2k-gate
$(OUT)/d2k-gate: main.c
	mkdir -p $(OUT)
	$(CC) $(CFLAGS) -o $@ main.c -lpthread

test: $(OUT)/test-gate
	$(OUT)/test-gate
$(OUT)/test-gate: test.c main.c
	mkdir -p $(OUT)
	$(CC) $(CFLAGS) -o $@ test.c -lpthread

# Статический бинарь для VPS (x86_64, без зависимостей).
vps: main.c
	mkdir -p $(OUT)
	$(ZIG) cc -target x86_64-linux-musl -O2 -std=c11 -Wall -Wextra -Werror -static -s -o $(OUT)/d2k-gate-x86_64 main.c
