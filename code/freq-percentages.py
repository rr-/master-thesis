#!/usr/bin/python
import sys, re

#ignoruj "broken pipe"
from signal import signal, SIGPIPE, SIG_DFL
signal(SIGPIPE,SIG_DFL)

total = 0
words = {}
for line in sys.stdin.readlines():
	(word, freq) = re.split(r',?\s+', line.strip())
	words[word] = int(freq)
	total += int(freq)

pad = max(len(word) for word in words.keys())
fmt = '%-' + str(pad) + 's %.05f%%'

for key in sorted(words.keys(), key=lambda x:words[x], reverse=True):
	value = words[key]
	percent = value*100.0/total
	print fmt % (key, percent)
