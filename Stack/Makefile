#
# Makefile for virtual stack executable
#

OBJS = netether.o netarp.o netip.o neticmp.o netudp.o nettcp.o processes.o stack.o 
LIBS = -L ../Arrays -L ../Events -L ../NetTAP -larrays -levents -ltap
CFLAGS += -I ../Arrays -I ../Events -I ../NetTAP

#
# Global target
#

all: stack

#
# Cleaning target
#

clean: 
	rm -f core *.o stack

#
# Executable target
#

stack: $(OBJS)
	$(CC) -o stack $(OBJS) $(LIBS)

stack.o: stack.c netether.h netip.h netarp.h neticmp.h netudp.h stack.h
netether.o: netether.c netether.h netip.h stack.h
netarp.o: netarp.c netether.h netip.h netarp.h stack.h
netip.o: netip.c netether.h netip.h neticmp.h stack.h
neticmp.o: neticmp.c netip.h neticmp.h stack.h
netudp.o: netudp.c netip.h neticmp.h stack.h
nettcp.o: nettcp.c netip.h stack.h
processes.o: processes.c netip.h stack.h

