CC=gcc
CFLAGS=-std=gnu99 -Wall -pedantic -O3 -I.. -funroll-loops -funit-at-a-time

all: md5coll
md5coll: *.c ../*.c

clean:
	rm -f md5coll
run: md5coll
	./md5coll
