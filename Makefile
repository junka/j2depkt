.PHONY: all clean
all: build/parser

clean:
	rm -r build

build:
	mkdir build

build/parser.c: parser.peg | build
	peg -P $^ > $@

build/parser: main.c | build/parser.c
	$(CC) -O2 -g -o $@ $^ -lpcap

build/parser_debug: main.c
	$(CC) -O2 -g -o $@ $^ -DYY_DEBUG -lpcap