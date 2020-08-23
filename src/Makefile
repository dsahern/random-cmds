
CC = gcc
LD = ld
CFLAGS = -O2 -g -Wall
LDFLAGS = -static
INCLUDES = -I.
CMDS = rps pktgen tap_recv

all: $(CMDS)

%.o: %.c
	$(CC) $(DEFS) $(CFLAGS) $(INCLUDES) -c $^ -o $@

%: %.o
	$(CC) $(LDFLAGS) $^ -o $@

pktgen: pktgen.o logging.o tap.o str_utils.o
	$(CC) $(LDFLAGS) $^ -o $@ -lpthread

tap_recv: tap_recv.o logging.o tap.o packet.o str_utils.o
	$(CC) $(LDFLAGS) $^ -o $@ -lpthread

clean:
	rm -rf $(CMDS) *.o
