#
# Makefile for TCP/IP stack
#

#
# Compilation constants
#

CC = gcc
LD = gcc
AR = ar
CFLAGS += -g -Wall -DVERBOSE #-DDEBUG_EVENTS
MAKE = make 
export CFLAGS

#
# Project constants
#

DIRS=Arrays Events NetTAP Stack

#
# Main target
#

all: $(patsubst %, _dir_%, $(DIRS))

$(patsubst %,_dir_%,$(DIRS)):
	cd $(patsubst _dir_%,%,$@) && $(MAKE)

#
# Cleaning target
#

clean: $(patsubst %, _clean_%, $(DIRS))

$(patsubst %,_clean_%,$(DIRS)):
	cd $(patsubst _clean_%,%,$@) && $(MAKE) clean
