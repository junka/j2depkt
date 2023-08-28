all: pcapfilter

clean:
	rm -f pcapfilter

pcapfilter: main.c
	$(CC) -O2 -g -o $@ $^ -I../../ -lpcap -L../../ -ldepkt