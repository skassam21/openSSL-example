CC := gcc
CFLAGS := -Wall
LIBS := -lssl -lcrypto
LDFLAGS := $(LIBS)
RM := rm -f

sources := client.c server.c 
targets := client server 

.PHONY: clean default all

default: all
all: $(targets)

client: client.o
	$(CC) -o client client.o $(LDFLAGS)

server: server.o
	$(CC) -o server server.o $(LDFLAGS)


client.o: client.c
	$(CC) $(CFLAGS) -c -o client.o client.c

server.o: server.c
	$(CC) $(CFLAGS) -c -o server.o  server.c

clean:
	$(RM) $(targets) $(sources:.c=.o) *~

