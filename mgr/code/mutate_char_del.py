from itertools import combinations

def mutate_char_del(str):
	for i in range(len(str), 0, -1):
		for p in combinations(list(str), i):
			yield ''.join(p)
