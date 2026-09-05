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
BUILD_CONFIG := $(OBJECT_DIR)/.build-config
TEST_OBJECTS := $(filter-out $(OBJECT_DIR)/main.o $(OBJECT_DIR)/server.o,$(OBJECTS))
SERVER_TEST := build/tests/$(BUILD_VARIANT)/server

define BUILD_CONFIG_CONTENT
CC=$(CC)
CPPFLAGS=$(CPPFLAGS)
PROJECT_CPPFLAGS=$(PROJECT_CPPFLAGS)
CFLAGS=$(CFLAGS)
PROJECT_CFLAGS=$(PROJECT_CFLAGS)
LDFLAGS=$(LDFLAGS)
PROJECT_LDLIBS=$(PROJECT_LDLIBS)
LDLIBS=$(LDLIBS)
endef

.PHONY: all clean check check-unit check-wolfssl check-ipset FORCE

all: $(TARGET)

$(TARGET): $(OBJECTS)
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) -o $@ $(OBJECTS) $(PROJECT_LDLIBS) $(LDLIBS)

$(OBJECT_DIR):
	@mkdir -p $@

$(BUILD_CONFIG): FORCE | $(OBJECT_DIR)
	$(file >$@.tmp,$(BUILD_CONFIG_CONTENT))
	@if cmp -s "$@.tmp" "$@"; then \
		rm -f "$@.tmp"; \
	else \
		mv -f "$@.tmp" "$@"; \
	fi

FORCE:

$(OBJECTS): $(BUILD_CONFIG)

$(OBJECT_DIR)/%.o: src/%.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(PROJECT_CPPFLAGS) $(CFLAGS) $(PROJECT_CFLAGS) -MMD -MP -c -o $@ $<

$(SERVER_TEST): tests/server.c src/server.c $(TEST_OBJECTS) $(BUILD_CONFIG)
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(PROJECT_CPPFLAGS) $(CFLAGS) $(PROJECT_CFLAGS) -UNDEBUG -MMD -MP $(LDFLAGS) -o $@ $< $(TEST_OBJECTS) $(PROJECT_LDLIBS) $(LDLIBS)

check-unit: $(SERVER_TEST)
	$(SERVER_TEST)

check: $(TARGET) check-unit
	python3 tests/e2e.py $(TARGET)

check-wolfssl:
	$(MAKE) WOLFSSL=1
	CHINADNS_TEST_DOT=1 python3 tests/e2e.py build/chinadns-ng+wolfssl

check-ipset: $(TARGET)
	CHINADNS_TEST_VERDICT=1 python3 tests/e2e.py $(TARGET)

clean:
	rm -rf build

-include $(OBJECTS:.o=.d)
-include $(SERVER_TEST).d
