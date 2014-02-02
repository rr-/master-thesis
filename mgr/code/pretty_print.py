def pretty_print(g, cols):
	g = list(g)
	m = [0,] * cols
	for i in xrange(len(g)):
		k = i % cols
		m[k] = max(m[k], len(g[i]))
	line = ''
	for i in xrange(len(g)):
		k = i % cols
		fmt = '%-' + str(m[k]) + 's   '
		line += fmt % (g[i])
		if k == cols-1:
			print line.strip()
			line = ''
	if line != '':
		print line.strip()

