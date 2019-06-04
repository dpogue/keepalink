CC=gcc
CFLAGS= -W -Wall -g
SOURCES= main.c
OUTNAME= keepalink

all:
	$(CC) $(CFLAGS) $(SOURCES) -o $(OUTNAME)

wine:
	wineg++ $(CFLAGS) $(SOURCES) -o $(OUTNAME) -lws2_32

clean:
	rm -f keepalink keepalink.exe keepalink.exe.so
