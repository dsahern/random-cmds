ifeq ("$(origin V)", "command line")
  VERBOSE = $(V)
endif
ifndef VERBOSE
  VERBOSE = 0
endif
ifeq ($(VERBOSE),1)
  Q =
else
  Q = @
endif

ifeq ($(VERBOSE), 0)
  QUIET_CC       = @echo '    CC       '$@;
  QUIET_LINK     = @echo '    LINK     '$@;
  QUIET_CLANG    = @echo '    CLANG    '$@;
  QUIET_LLC      = @echo '    LLC      '$@;
endif

ifneq (,$(BUILDDIR))
OBJDIR = $(BUILDDIR)/src/obj/
else
OBJDIR = obj/
endif

ifneq (,$(BUILDDIR))
BINDIR = $(BUILDDIR)/src/bin/
else
BINDIR = bin/
endif

CC = gcc
CFLAGS = -O2 -g -Wall
LDFLAGS = -static
INCLUDES = -I. -Iinclude/uapi

CMDS = $(BINDIR)rps
CMDS += $(BINDIR)pktgen
CMDS += $(BINDIR)tap_recv
CMDS += $(BINDIR)tap_fwd
CMDS += $(BINDIR)cpumon
CMDS += $(BINDIR)nettest
CMDS += $(BINDIR)pkt-check

COMMON += $(OBJDIR)logging.o
COMMON += $(OBJDIR)str_utils.o
COMMON += $(OBJDIR)raw_input.o

all: build $(CMDS)

build:
	@mkdir -p $(OBJDIR) $(BINDIR)

$(OBJDIR)%.o: %.c
	$(QUIET_CC)$(CC) $(DEFS) $(CFLAGS) $(INCLUDES) -c $^ -o $@

$(BINDIR)%: $(OBJDIR)%.o $(COMMON)
	$(QUIET_LINK)$(CC) $(LDFLAGS) $^ -o $@

$(BINDIR)pktgen: $(OBJDIR)pktgen.o $(OBJDIR)tap.o $(COMMON)
	$(QUIET_LINK)$(CC) $(LDFLAGS) $^ -o $@ -lpthread

$(BINDIR)pkt-check: $(OBJDIR)pkt-check.o
	$(QUIET_LINK)$(CC) $^ -o $@ -lpcap

$(BINDIR)tap_%: $(OBJDIR)tap_%.o $(OBJDIR)tap.o $(OBJDIR)packet.o $(COMMON)
	$(QUIET_LINK)$(CC) $(LDFLAGS) $^ -o $@ -lpthread

clean:
	@rm -rf $(OBJDIR) $(BINDIR)
