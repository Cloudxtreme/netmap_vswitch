TARGETS := test_recv

test_recv_OBJECTS = objs/test_recv.o 

CFLAGS = -g -Wall -rdynamic
CC = gcc
NM = nm
INCLUDES= -I$(root_dir)/include/
LIBS_INCLUDE = -L$(root_dir)/lib/
LIBS = -ldl -lm -lnetmap
COMPILE = $(CC) $(CFLAGS) $(INCLUDES)
LINK = $(COMPILE) -o $@

all: $(TARGETS)

test_recv: $(test_recv_OBJECTS)
	$(LINK) $(test_recv_OBJECTS) $(LIBS) $(LIBS_INCLUDE)

objs/test_recv.o:test_recv.c
	$(COMPILE) -c -o $@ $<

clean:
	- rm -rf objs .tmp*
	- rm -f $(TARGETS)

