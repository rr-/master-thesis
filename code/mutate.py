#!/usr/bin/python
from pretty_print import pretty_print
import re
import sys

x = [
	("mutate_alpha('abcd')", 2),
	("mutate_infix('abc', ['0', '1', '2'])", 3),
	("mutate_suffix('abc', [str(i) for i in range(10)] + ['123', '2000', '2001', '2013'])", 3),
	("mutate_char_sub('leet', {'l':['L','1'], 'e':['E','3'], 't':['T','7']})", 6),
]

for v in x:
	v, cols = v
	k = re.findall('\w+', v)[0]
	exec('from ' +  k + ' import ' + k)
	v = ['pretty_print(' + v + ',' + str(cols) + ')']
	sys.stdout = open(k + '.txt', 'w')
	print "\n".join('>>>' + line for line in v)
	exec "\n".join(v) in locals(), locals()
