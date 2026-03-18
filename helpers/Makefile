# Makefile for TUN and ICMP helpers

CC ?= cc
CFLAGS = -O2 -Wall -Wextra

.PHONY: all clean

all:
	@if [ "$$(uname)" = "Darwin" ]; then \
		$(CC) $(CFLAGS) -o utun-helper utun-helper.c; \
		echo "Built utun-helper for macOS"; \
	elif [ "$$(uname)" = "Linux" ]; then \
		$(CC) $(CFLAGS) -o tun-helper tun-helper-linux.c; \
		echo "Built tun-helper for Linux"; \
		$(CC) $(CFLAGS) -o icmp-helper icmp-helper.c; \
		echo "Built icmp-helper for Linux"; \
	else \
		echo "Unsupported platform"; \
	fi

clean:
	rm -f utun-helper tun-helper icmp-helper
