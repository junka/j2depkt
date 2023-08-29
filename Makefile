

OBJ = depktcap.o utils.o
CFLAGS += -fPIC


.PHONY: all clean

all: libdepkt.a



clean:
	rm -f *.o
	rm -f parser.c

parser.c: parser.peg
	peg -P $^ > $@

depktcap.o: depktcap.c parser.c
	$(CC) -c -o $@ depktcap.c $(CFLAGS) -Wall -O2

utils.o: utils.c
	$(CC) -c -o $@ utils.c $(CFLAGS) -Wall -O2

dpdkrflow.o: dpdkrflow.c parser.c
	$(CC) -c -o $@ dpdkrflow.c $(CFLAGS) -Wall -O2

libdepkt.a: $(OBJ)
	$(AR) -rc $@ $(OBJ)

