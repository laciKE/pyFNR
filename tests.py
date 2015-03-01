import unittest
import math
import random
import string
import pyFNR

class TestConversions(unittest.TestCase):

	def setUp(self):
		# prepare one instance for each block_size
		self.fnr = [(i, pyFNR.FNR(block_size=i)) for i in range(1, 129)]

	def tearDown(self):
		for fnr in self.fnr:
			fnr[1].close()

	def test_integers_to_bytes_conversion_and_vice_versa(self):
		for item in self.fnr:
			block_size = item[0]
			# compute number of bytes for block_size in bits
			block_size_bytes = int(math.ceil(block_size*1.0/8))
			fnr = item[1]
			# choose up to 100 random ints for converting
			ints = [random.randrange(0, 2**block_size) for i in range(min(100,2**block_size))]
			for p in ints:
				c = fnr._int_to_bytes(p)
				# check correct type
				self.assertEqual(type(c), bytearray)
				# check correct block size
				self.assertEqual(len(c), block_size_bytes)
				p2 = fnr._bytes_to_int(c)
				# check correct conversion back to int
				self.assertEqual(p, p2)

	def test_strings_to_bytes_conversion_and_vice_versa(self):
		for item in self.fnr:
			block_size = item[0]
			# compute number of bytes for block_size in bits
			block_size_bytes = int(math.ceil(block_size*1.0/8))
			fnr = item[1]
			# choose up to 100 random strings for converting
			strs = ["".join(random.choice(string.printable) for i in range(block_size_bytes)) for i in range(min(100,2**block_size))]
			for p in strs:
				c = fnr._str_to_bytes(p)
				# check correct type
				self.assertEqual(type(c), bytearray)
				# check correct block size
				self.assertEqual(len(c), block_size_bytes)
				p2 = fnr._bytes_to_str(c)
				# check correct conversion back to int
				self.assertEqual(p, p2)

if __name__ == '__main__':
	unittest.main()
