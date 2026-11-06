CC ?= cc
CPPFLAGS += -D_DEFAULT_SOURCE -Isrc
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Werror
LDLIBS += -lssl -lcrypto

.PHONY: all test integration clean
all: build/taglink
build:
	mkdir -p $@
build/taglink: src/relay.c src/control.c src/segment.c src/taglink.h src/control.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(filter %.c,$^) $(LDLIBS) -o $@
build/check: tests/check.c src/control.c src/segment.c src/taglink.h src/control.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(filter %.c,$^) $(LDLIBS) -o $@
test: all build/check
	./tests/check.sh
integration: all
	./tests/lab.sh
clean:
	rm -rf build
