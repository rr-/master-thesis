from itertools import permutations

def mutate_perm(str):
	for p in permutations(list(str)):
		yield ''.join(p)
