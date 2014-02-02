from itertools import product

def mutate_alpha(str):
	l = len(str)
	lower = str.lower()
	upper = str.upper()
	for p in product([False, True], repeat=len(str)):
		yield ''.join(upper[i] if p[i] else lower[i] for i in xrange(l))
