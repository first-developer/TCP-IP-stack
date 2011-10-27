#
# Makefile for the event library
#

OBJS = libevents.o

all: libevents.a

#
# Cleaning target
#

clean: 
	rm -f core *.o libevents.a

#
# Library target
#

libevents.o: libevents.c libevents.h
 
libevents.a: $(OBJS)
	rm -f $@
	$(AR) rcs $@ $+
