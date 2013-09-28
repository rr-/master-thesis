def mutate_char_insert(input, alpha):
	yield input
	alpha = list(alpha) if isinstance(alpha, basestring) else alpha
	for x in xrange(len(input)):
		for y in xrange(len(alpha)):
			yield input[:x] + alpha[y] + input[x:]
