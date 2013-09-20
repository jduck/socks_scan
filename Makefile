PKG = socks_scan
VERSION = 1.0

# ninja socket library location
NSOCKDIR = ../libnsock

CC = gcc
INCLUDES = -I. -I$(NSOCKDIR)
DEFINES = -DVERSTR=\"$(VERSION)\"
CFLAGS = -Wall -O2 $(INCLUDES) $(DEFINES)
# CFLAGS = -Wall -ggdb -DSOCKS_DEBUG $(INCLUDES) $(DEFINES)
# CFLAGS = -Wall -ggdb $(INCLUDES) $(DEFINES)
LDFLAGS = -lm -lnsock -L$(NSOCKDIR)

SRCS = socks5.c socks4.c socks_scan.c args.c targets.c
OBJS = socks5.o socks4.o socks_scan.o args.o targets.o

# all targets
#
all: $(PKG)

.c.o:
	$(CC) $(CFLAGS) -c $<

$(PKG): $(OBJS)
	$(CC) $(CFLAGS) -o $(PKG) $^ $(LDFLAGS)

clean:
	rm -f $(OBJS) $(PKG)

distclean: clean
	rm -f .gdb_history

dist: distclean
	cd ..; tar zcvvf $(PKG)-$(VERSION).tgz --exclude $(PKG)/no_dist $(PKG)
	
depend:
	gcc $(INCLUDES) -MM *.c | sed 's,$(NSOCKDIR),$$(NSOCKDIR),g' >> Makefile


# auto-generated with gcc -MM *.c
#
args.o: args.c targets.h args.h defs.h $(NSOCKDIR)/nsock_tcp.h \
  $(NSOCKDIR)/nsock.h $(NSOCKDIR)/nsock_defs.h \
  $(NSOCKDIR)/nsock_resolve.h
socks4.o: socks4.c socks4.h socks.h
socks5.o: socks5.c socks5.h socks.h
socks_scan.o: socks_scan.c socks4.h socks.h socks5.h targets.h args.h \
  defs.h $(NSOCKDIR)/nsock_tcp.h $(NSOCKDIR)/nsock.h \
  $(NSOCKDIR)/nsock_defs.h
targets.o: targets.c socks.h args.h defs.h targets.h \
  $(NSOCKDIR)/nsock_resolve.h $(NSOCKDIR)/nsock.h \
  $(NSOCKDIR)/nsock_defs.h
