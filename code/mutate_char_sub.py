from itertools import product

def mutate_char_sub(s, subs):
	for x in s:
		if x not in subs:
			subs[x] = x
		elif x not in subs[x]:
			subs[x].append(x)
	args = [subs[x] for x in s]
	return (''.join(o) for o in product(*args))

for m in mutate_char_sub('leet', {'l': ['L', '1'], 'e': ['E', 'e'], 't': ['T', '7']}):
	print m
