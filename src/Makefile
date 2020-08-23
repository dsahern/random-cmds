
CC = gcc
LD = ld
CFLAGS = -O2 -g -Wall
LDFLAGS = -static
INCLUDES = -I.

all: rps pktgen

%.o: %.c
	$(CC) $(DEFS) $(CFLAGS) $(INCLUDES) -c $^ -o $@

%: %.o
	$(CC) $(LDFLAGS) $^ -o $@

pktgen: pktgen.o logging.o tap.o
	$(CC) $(LDFLAGS) $^ -o $@ -lpthread

clean:
	rm -rf rps pktgen *.o
