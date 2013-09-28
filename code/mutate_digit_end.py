def mutate_digit_end(input):
	yield input
	for x in xrange(10):
		yield input+str(x)
