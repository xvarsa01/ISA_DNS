CC = gcc
CFLAGS = -Wall -Wextra -pedantic -std=gnu99

SRCS = $(wildcard *.c)
EXECUTABLES = dns-monitor

all: $(EXECUTABLES)

dns-monitor: $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) -lpcap

clean:
	rm -f $(EXECUTABLES)