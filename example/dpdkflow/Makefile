

CFLAGS=-O2 -g -Wall -Wextra $(shell pkg-config --libs --static libdpdk)
all: dpdkflow

clean:
	rm -f dpdkflow

dpdkflow: main.c
	$(CC) -o $@ $^ -I../../ -L../../ -ldepkt_dpdk -lpthread $(CFLAGS)