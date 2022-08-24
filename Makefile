CC = gcc
CFLAGS = 
CLIBS = 
CMDS = packetCapture

all : $(CMDS)

packetCapture : packetCapture.c
	$(CC) $(CFLAGS) $^ -o $@ $(CLIBS) -lpthread -W

clean :
	rm $(CMDS) core
