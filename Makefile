SOURCES := ddnsclient.c httprequest.c log.c daemon.c

OBJS := $(SOURCES:.c=.o)

LIBS ?= -lssl -lcrypto

PROGRAM := ddnsclient

CC ?= gcc

CFLAGS += -O2 -Wall

.PHONY: clean all

all: $(PROGRAM)

$(PROGRAM): $(OBJS)
	$(CC) $(CFLAGS) -o $(PROGRAM) $(OBJS) $(LFLAGS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $<

clean:
	rm $(OBJS)
