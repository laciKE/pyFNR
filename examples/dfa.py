import pyFNR
import pyFNR.Util

"""
Example of custom format: regular language with symbols 'a', 'b' such that
number of 'a' is divisible by 3 and number of 'b' is divisible by 2.
"""

# properties of custom DFA
Q = [(count_a, count_b) for count_a in range(3) for count_b in range(2)]
Sigma = ['a', 'b']
def delta(q, c):
	count_a, count_b = q[0], q[1]
	if c == 'a':
		count_a = (count_a + 1) % 3
	if c == 'b':
		count_b = (count_b + 1) % 2
	return (count_a, count_b)
q_0 = (0, 0)
F = [(0, 0)]

dfa = pyFNR.Util.DFA(Q, Sigma, delta, q_0, F)
myFormat = pyFNR.Util.FPE_Format(dfa, 12) # words with length 12

fnr = pyFNR.FNR2(key='password', tweak='tweak-is-string', domain=myFormat.get_words_count()-1)

plains = ['bbaaabbaaabb', 'aaaaaaaaaaaa', 'aaaaaabbbbbb', 'bbbbbbbbbbbb']
for plain in plains:
	cipher = myFormat.unrank(fnr.encrypt(myFormat.rank(plain)))
	plain2 = myFormat.unrank(fnr.decrypt(myFormat.rank(cipher)))
	print(plain + ' -> ' + cipher + ' -> ' +plain2)

fnr.close()
