CC = gcc
CFLAGS = 
CLIBS = 
CMDS = 20170800

all : $(CMDS)

20170800 : 20170800.c
	$(CC) $(CFLAGS) $^ -o $@ $(CLIBS) -lpthread -W

clean :
	rm $(CMDS) core
