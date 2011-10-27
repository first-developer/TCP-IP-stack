#
# Makefile for the tap library
#

OBJS = libtap.o

all: libtap.a

#
# Cleaning target
#

clean: 
	rm -f core *.o libtap.a

#
# Library target
#

libtap.o: libtap.c libtap.h
 
libtap.a: $(OBJS)
	rm -f $@
	$(AR) rcs $@ $+
