def mutate_suffix(s, suffixes):
	yield s
	for x in suffixes:
		yield s+x
