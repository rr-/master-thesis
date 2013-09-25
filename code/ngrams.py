#!/usr/bin/python
import sys
import re
import string
from itertools import product

alpha = string.ascii_lowercase
nums = [1, 2, 3]

def ngram(word, n):
	for i in xrange(len(word)+1-n):
		yield word[i:i+n]

ngrams = {}
for n in nums:
	ngrams[n] = {}
	for key in product(alpha, repeat=n):
		key = ''.join(key)
		ngrams[n][key] = 0

regex = '[%s\']+' % alpha
for line in sys.stdin.readlines():
	words = re.findall(regex, line)
	for word in words:
		word = re.sub('\'', '', word)
		word = word.lower()
		for n in nums:
			for key in ngram(word, n):
				ngrams[n][key] += 1

total = {}
pad1 = pad2 = 0
for n, ngram in ngrams.iteritems():
	total[n] = sum(ngram.values())
	pad1 = max(pad1, n)
	pad2 = max(pad2, len(str(max(ngram.values()))))
format  = '%' + str(pad1) + 's: '
format += '%' + str(pad2) + 'd (%.05f%%)'

for n, ngram in ngrams.iteritems():
	keys = sorted(ngram, key=ngram.get, reverse=True)
	for key in keys:
		value = ngram[key]
		if value > 0:
			percent = value * 100.0 / total[n]
			print format % (key, value, percent)
	print
