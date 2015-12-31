CFLAGS = -g
CFLAGS += -fPIC -Wall -Wunused-function -Wextra
INCLUDES= -I$(root_dir)/include/

LIB=libnetmap.so

all: $(LIB)

LIBOBJS=nmv_skb.o

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ -c $<

$(LIB):$(LIBOBJS)
	$(CC) $(LIBS) -shared -o $@ $^

clean:
	-@rm -rf $(LIB) *.o
