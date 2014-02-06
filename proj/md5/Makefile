CC=gcc
CFLAGS=-Wall -pedantic -O3 -I.. -funroll-loops -funit-at-a-time

all: md5coll
md5coll: md5coll.c ../common.c ../sc.c

clean:
	rm -f md5coll
run: md5coll
	./md5coll
