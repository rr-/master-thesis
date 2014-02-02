def mutate_infix(s, alpha):
	yield s
	for x in xrange(len(s)):
		for y in alpha:
			yield s[:x] + y + s[x:]
