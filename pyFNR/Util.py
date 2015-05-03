"""
Module with support for various common formats for FPE.

Format can be represented as a regular language described by a DFA.
For each format this module contains separate class with rank()
and unrank() methods for converting words from desired regular
language to integers and vice versa.
"""

import struct
import socket
import binascii
import math

class DFA(object):
	"""
	DFA(Q, Sigma, delta, q0, F) -> DFA object

	Represents deterministic finite automaton.

	Arguments:
	Q -- list of states
	Sigma -- (ordered) list of input symbols (chars)
	delta -- transition function
		can be adictionary with tuples (state, symbol) as keys and state
		from Q as values or function (state, symbol) -> state
	q0 -- start state from Q
	F -- list of accept states, a subset of Q
	"""

	def __init__(self, Q, Sigma, delta, q0, F):
		"""
		Constructor of DFA class. For parameter description see DFA.__doc__
		"""
		if not (q0 in Q):
			raise ValueError("Unknown initial state: " + str(q0))
		for q in F:
			if not (q in Q):
				raise ValueError("Unknown final state: " + str(q))

		if (type(delta) == dict):
			_delta = {}
			for q,chars in delta.keys():
				for a in chars:
					_delta[(q,a)] = delta[q,chars]
			for q,a in _delta.keys():
				if not (q in Q):
					raise ValueError("Unknown state in delta function: " + str(q))
				if not (a in Sigma):
					raise ValueError("Unknown character in delta function: " + str(a))

		#change states to numbers
		self.Q = range(len(Q) + 1)
		self.invalid_q = len(Q) #last state is invalid state
		Q_ord = dict(zip(Q, self.Q))
		self.Sigma = Sigma
		self.Sigma_ord = dict(zip(Sigma, range(len(Sigma))))
		self.q0 = Q_ord[q0]
		self.F = [Q_ord[q] for q in F]
		if (type(delta) == dict):
			self._delta = dict([((Q_ord[q], a), Q_ord[_delta[(q,a)]]) for q,a in _delta.keys()])
		else:
			self._delta = delta
			self.Q_ord = Q_ord
			self.Q_chr = Q

	def delta(self, q, char):
		"""
		delta(state, symbol) -> state

		Transition function constructed from parameter delta of constructor.
		"""
		if (q == self.invalid_q):
			return self.invalid_q
		if (type(self._delta) == dict):
			if (q, char) in self._delta:
				return self._delta[(q, char)]
			else:
				return self.invalid_q
		else:
			return self.Q_ord[self._delta(self.Q_chr[q], char)]

	def ord(self, char):
		"""
		ord(char) -> int

		Returns the integer ordinal of a given symbol.
		"""
		return self.Sigma_ord[char]

	def chr(self, i):
		"""
		chr(int) -> char

		Returns the symbol with given integer ordinal.
		"""
		return self.Sigma[i]


class FPE_Format(object):
	"""
	Base class for classes uses formats described by DFA.

	Arguments:
	DFA -- DFA object for desired format (regular language).
	N -- exact length of words from regular language
	"""

	def __init__(self, DFA, N):
		"""
		Constructor of FPE_Format class. For parameter description
		see FPE_Format.__doc__
		"""
		self.DFA = DFA
		self.N = N
		self.__buildTable(N)
		self.words_count = self.T[0][N]

	def __buildTable(self, N):
		DFA = self.DFA
		self.T = [[0]*(N+1) for _ in range(len(DFA.Q))]
		for q in DFA.Q:
			if q in DFA.F:
				self.T[q][0] = 1
		for i in range(1, N+1):
			for q in DFA.Q:
				for a in DFA.Sigma:
					self.T[q][i] += self.T[DFA.delta(q, a)][i-1]

	def rank(self, X):
		"""
		rank(str) -> int

		Returns integer ordinal of given word in sorted list of all words
		from regular language
		"""
		DFA = self.DFA
		q = DFA.q0
		c = 0
		N = self.N
		for i in range(N):
			for j in range(0, DFA.ord(X[i])):
				c += self.T[DFA.delta(q, DFA.Sigma[j])][N-i-1]
			q = DFA.delta(q, X[i])
		if q == DFA.invalid_q:
			raise ValueError('Invalid word ' + X)
		return c

	def unrank(self, c):
		"""
		unrank(int) -> str

		Returns word with given integer ordinal in sorted list of all
		words from regular language.
		"""
		DFA = self.DFA
		X = ''
		N = self.N
		q = DFA.q0
		j = 0
		for i in range(self.N):
			while c >= self.T[DFA.delta(q, DFA.Sigma[j])][N-i-1]:
				c -= self.T[DFA.delta(q,DFA.Sigma[j])][N-i-1]
				j += 1
			X += DFA.Sigma[j]
			q = DFA.delta(q, X[i])
			j = 0
		return X

	def get_words_count(self):
		"""
		get_words_count() -> int

		Returns the number of words in given regular language with
		length equal to N
		"""
		return self.words_count


class IPv4(FPE_Format):
	"""
	Class for IPv4 format.
	"""

	def __init__(self):
		self.words_count = 2**32

	def rank(self, ipv4):
		"""
		rank(str) -> int

		Returns integer ordinal of given word in sorted list of all words
		from regular language
		"""
		return struct.unpack('!I', socket.inet_aton(ipv4))[0]

	def unrank(self, c):
		"""
		unrank(int) -> str

		Returns word with given integer ordinal in sorted list of all
		words from regular language.
		"""
		return socket.inet_ntoa(struct.pack('!I', c))


class IPv6(FPE_Format):
	"""
	Class for IPv9 format.
	"""

	def __init__(self):
		self.words_count = 2**128

	def rank(self, ipv6):
		"""
		rank(str) -> int

		Returns integer ordinal of given word in sorted list of all words
		from regular language
		"""
		h, l = struct.unpack('!QQ', socket.inet_pton(socket.AF_INET6, ipv6))
		return (h << 64) | l
		#return int(binascii.hexlify(socket.inet_pton(socket.AF_INET6, ipv6)), 16)

	def unrank(self, c):
		"""
		unrank(int) -> str

		Returns word with given integer ordinal in sorted list of all
		words from regular language.
		"""
		h = (c >> 64)
		l = c ^ (h << 64)
		return socket.inet_ntop(socket.AF_INET6, struct.pack('!QQ', h, l))
		#return socket.inet_ntop(socket.AF_INET6, '{0:016x}'.format(c))


class LuhnR(FPE_Format):
	"""
	Class for LuhnR_M language: reversals of numbers with Luhn checksum
	equals to M.

	LuhnR_0 language is suitable for credit cards numbers.
	LuhnR_M language is suitable for part of credit cards numbers,
	e.g. for first k digits of CCN
	"""
	def __init__(self, M, N):
		"""
		M -- desired value of Luhn checksum
		N -- length of string representations numbers
		"""
		Q = []
		for a in range(10):
			for b in range(2):
				Q.append((a, b))
		Sigma = [str(i) for i in range(10)]
		def delta(t, c):
			a, b = t[0], t[1]
			c = ord(c) - ord('0')
			return ((a+c+(1-b)*(c+int(math.floor(1.0*c/5))))%10 , 1-b)
		dfa = DFA(Q, Sigma, delta, (0,0), [(M,0), (M,1)])
		super(LuhnR, self).__init__(dfa, N)


class ECV(FPE_Format):
	"""
	Class for car license plate coding in Slovakia (Evidencne cislo
	vozidla -- ECV)
	"""
	def __init__(self):
		Q = ['_BCDGHIKLMNPRSTVZ',
			'B_ABJLNRSY', 'C_A', 'D_KST', 'G_AL', 'H_CE', 'I_L', 'K_AEKMNS',
			'L_CEMV', 'M_AILTY', 'N_RMOZ', 'P_BDEKNOPTU', 'R_AKSV',
			'S_ABCEIKLNOPV', 'T_TNORSV', 'V_KT', 'Z_ACHMV',
			'city_d1', 'd1_d2', 'd2_d3', 'd3_c1', 'c1_c2', 'ECV_final']
		Sigma = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
				'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
				'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
				'W', 'X', 'Y', 'Z']
		delta = {('_BCDGHIKLMNPRSTVZ', ('B')): 'B_ABJLNRSY', 
				('_BCDGHIKLMNPRSTVZ', ('C')): 'C_A',
				('_BCDGHIKLMNPRSTVZ', ('D')): 'D_KST',
				('_BCDGHIKLMNPRSTVZ', ('G')): 'G_AL',
				('_BCDGHIKLMNPRSTVZ', ('H')): 'H_CE',
				('_BCDGHIKLMNPRSTVZ', ('I')): 'I_L',
				('_BCDGHIKLMNPRSTVZ', ('K')): 'K_AEKMNS',
				('_BCDGHIKLMNPRSTVZ', ('L')): 'L_CEMV',
				('_BCDGHIKLMNPRSTVZ', ('M')): 'M_AILTY',
				('_BCDGHIKLMNPRSTVZ', ('N')): 'N_RMOZ',
				('_BCDGHIKLMNPRSTVZ', ('P')): 'P_BDEKNOPTU',
				('_BCDGHIKLMNPRSTVZ', ('R')): 'R_AKSV',
				('_BCDGHIKLMNPRSTVZ', ('S')): 'S_ABCEIKLNOPV',
				('_BCDGHIKLMNPRSTVZ', ('T')): 'T_TNORSV',
				('_BCDGHIKLMNPRSTVZ', ('V')): 'V_KT',
				('_BCDGHIKLMNPRSTVZ', ('Z')): 'Z_ACHMV',
				('B_ABJLNRSY', ('A', 'B', 'J', 'L', 'N', 'R', 'S', 'Y')): 'city_d1',
				('C_A', ('A')): 'city_d1',
				('D_KST', ('K', 'S', 'T')): 'city_d1',
				('G_AL', ('A', 'L')): 'city_d1',
				('H_CE', ('C', 'E')): 'city_d1',
				('I_L', ('L')): 'city_d1',
				('K_AEKMNS', ('A', 'E', 'K', 'M', 'N', 'S')): 'city_d1',
				('L_CEMV', ('C', 'E', 'M', 'V')): 'city_d1',
				('M_AILTY', ('A', 'I', 'L', 'T', 'Y')): 'city_d1',
				('N_RMOZ', ('R', 'M', 'O', 'Z')): 'city_d1',
				('P_BDEKNOPTU', ('B', 'D', 'E', 'K', 'N', 'O', 'P', 'T', 'U')): 'city_d1',
				('R_AKSV', ('A', 'K', 'S', 'V')): 'city_d1',
				('S_ABCEIKLNOPV', ('A', 'B', 'C', 'E', 'I', 'K', 'L', 'N', 'O', 'P', 'V')): 'city_d1',
				('T_TNORSV', ('T', 'N', 'O', 'R', 'S', 'V')): 'city_d1',
				('V_KT', ('K', 'T')): 'city_d1',
				('Z_ACHMV', ('A', 'C', 'H', 'M', 'V')): 'city_d1',
				('city_d1', ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9') ): 'd1_d2',

				('d1_d2', ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9') ): 'd2_d3',
				('d2_d3', ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9') ): 'd3_c1',
				('d3_c1', ('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z')): 'c1_c2',
				('c1_c2', ('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z')): 'ECV_final'
		}
		dfa = DFA(Q, Sigma, delta, '_BCDGHIKLMNPRSTVZ', ['ECV_final'])
		super(ECV, self).__init__(dfa, 7)
