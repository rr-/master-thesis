CC=gcc
CFLAGS=-std=gnu99 -Wall -pedantic -O3 -I.. -funroll-loops -funit-at-a-time

all: md4coll
md4coll: md4coll.c ../common.c ../sc.c ../tick.c

clean:
	rm -f md4coll
run: md4coll
	./md4coll
