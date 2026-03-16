# Makefile for utun-helper (macOS only)

CC ?= cc
CFLAGS = -O2 -Wall -Wextra

.PHONY: all clean

all: utun-helper

utun-helper: utun-helper.c
	@if [ "$$(uname)" = "Darwin" ]; then \
		$(CC) $(CFLAGS) -o $@ $<; \
		echo "Built utun-helper for macOS"; \
	else \
		echo "Skipping utun-helper build (not macOS)"; \
	fi

clean:
	rm -f utun-helper
