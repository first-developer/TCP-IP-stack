#
# Makefile for the associative arrays library
#

OBJS = libarrays.o

all: libarrays.a

#
# Cleaning target
#

clean: 
	rm -f core *.o libarrays.a

#
# Library target
#

libarrays.o: libarrays.c libarrays.h
 
libarrays.a: $(OBJS)
	rm -f $@
	$(AR) rcs $@ $+
