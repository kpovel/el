CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -Wpedantic -O2 -std=c11 -D_GNU_SOURCE
LDFLAGS ?=
LIBS     = -lsystemd -lssl -lcrypto

SRCDIR = src
SRCS   = $(SRCDIR)/main.c $(SRCDIR)/ble.c $(SRCDIR)/crypto.c $(SRCDIR)/protocol.c $(SRCDIR)/keydata.c
OBJS   = $(SRCS:.c=.o)
BIN    = grid_monitor

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

$(SRCDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(BIN)

.PHONY: all clean
