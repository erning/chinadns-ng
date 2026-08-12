CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -O2 -g
LDFLAGS ?=
LDLIBS ?=

PROJECT_CPPFLAGS := -Isrc
PROJECT_CFLAGS := -std=gnu11 -Wall -Wextra -fno-strict-aliasing
PROJECT_LDLIBS :=

ifeq ($(MUSL),1)
PROJECT_CPPFLAGS += -DMUSL
endif

ifeq ($(WOLFSSL),1)
PROJECT_CPPFLAGS += -DENABLE_WOLFSSL
PROJECT_LDLIBS += -lwolfssl
BUILD_VARIANT := wolfssl
TARGET ?= build/chinadns-ng+wolfssl
else
BUILD_VARIANT := default
TARGET ?= build/chinadns-ng
endif

SOURCES := \
	src/main.c \
	src/core.c \
	src/config.c \
	src/server.c \
	src/cache.c \
	src/local_rr.c \
	src/dns.c \
	src/dnl.c \
	src/ipset.c \
	src/nl.c \
	src/net.c \
	src/tag.c \
	src/log.c \
	src/misc.c

OBJECT_DIR := build/obj/$(BUILD_VARIANT)
OBJECTS := $(SOURCES:src/%.c=$(OBJECT_DIR)/%.o)

.PHONY: all clean check check-wolfssl check-ipset

all: $(TARGET)

$(TARGET): $(OBJECTS)
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) -o $@ $(OBJECTS) $(PROJECT_LDLIBS) $(LDLIBS)

$(OBJECT_DIR)/%.o: src/%.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(PROJECT_CPPFLAGS) $(CFLAGS) $(PROJECT_CFLAGS) -MMD -MP -c -o $@ $<

check: $(TARGET)
	python3 tests/e2e.py $(TARGET)

check-wolfssl:
	$(MAKE) WOLFSSL=1
	CHINADNS_TEST_DOT=1 python3 tests/e2e.py build/chinadns-ng+wolfssl

check-ipset: $(TARGET)
	CHINADNS_TEST_VERDICT=1 python3 tests/e2e.py $(TARGET)

clean:
	rm -rf build

-include $(OBJECTS:.o=.d)
