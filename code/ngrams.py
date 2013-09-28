#!/usr/bin/python
import sys, re
import string

#ignoruj "broken pipe"
from signal import signal, SIGPIPE, SIG_DFL
signal(SIGPIPE,SIG_DFL)

num = int(sys.argv[1])
alpha = string.ascii_lowercase

def ngram(word, n):
	for i in xrange(len(word)+1-n):
		yield word[i:i+n]

regex = '[%s\']+' % alpha
ngrams = {}
for line in sys.stdin.readlines():
	words = re.findall(regex, line)
	for word in words:
		word = re.sub('\'', '', word).lower()
		for key in ngram(word, num):
			if key not in ngrams:
				ngrams[key] = 0
			ngrams[key] += 1

if len(ngrams) == 0:
	sys.exit(0)

total = sum(ngrams.values())
pad = len(str(max(ngrams.values())))
fmt = '%s: %' + str(pad) + 'd (%.05f%%)'

keys = sorted(ngrams, key=ngrams.get, reverse=True)
for key in keys:
	value = ngrams[key]
	if value > 0:
		percent = value * 100.0 / total
		print fmt % (key, value, percent)
