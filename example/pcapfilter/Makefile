all: pcapfilter

clean:
	rm -f pcapfilter

pcapfilter: main.c | ../../build/parser.c
	$(CC) -O2 -g -o $@ $^ -lpcap

pcapfilter_debug: main.c
	$(CC) -O2 -g -o $@ $^ -DYY_DEBUG -lpcap