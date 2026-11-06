CC ?= cc
CPPFLAGS := -Iinclude
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror
SOURCES := src/main.c src/rules.c src/predicates.c src/decode.c src/capture.c
HEADERS := include/detector.h include/rules.h src/suricata_matchers.inc

.PHONY: all static check sanitize verify clean
all: static

static: bin/packet-detector

bin/packet-detector: $(SOURCES) $(HEADERS)
	mkdir -p bin
	$(CC) $(CPPFLAGS) $(CFLAGS) -static -o $@ $(SOURCES) $(LDFLAGS)

bin/packet-detector-asan: $(SOURCES) $(HEADERS)
	mkdir -p bin
	$(CC) $(CPPFLAGS) -std=c11 -O1 -g -Wall -Wextra -Wpedantic -Werror -fno-omit-frame-pointer -fno-pie -no-pie -fsanitize=address,undefined -o $@ $(SOURCES)

verify:
	python3 tools/extract_upstream.py --verify

check: bin/packet-detector verify
	python3 tests/test_detector.py --binary bin/packet-detector

sanitize: bin/packet-detector-asan
	ASAN_OPTIONS=detect_leaks=0 python3 tests/test_detector.py --binary bin/packet-detector-asan

clean:
	rm -f bin/packet-detector bin/packet-detector-asan
