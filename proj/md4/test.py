#!/usr/bin/python
import hashlib
import sys

hashes = []
lines = [line.strip() for line in sys.stdin.readlines()]
for line in lines:
	msg = line.decode('hex')
	hashes.append(hashlib.new("md4", msg).hexdigest().upper())

for line in lines:
	print line
for hash in hashes:
	print hash

print len(set(lines)) == len(lines)
print len(set(hashes)) == 1
