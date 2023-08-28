.PHONY: all clean
all: build/parser.c

clean:
	rm -r build

build:
	mkdir build

build/parser.c: parser.peg | build
	peg -P $^ > $@
