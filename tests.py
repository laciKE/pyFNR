import unittest
import math
import random
import string
import ctypes
import pyFNR

TEST_COUNT = 10

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
			# choose up to TEST_COUNT random ints for converting
			ints = Helper.generate_random_ints(0, 2**block_size, min(TEST_COUNT,2**block_size))
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
			# choose up to TEST_COUNT random strings for converting
			strs = Helper.generate_random_strings(block_size_bytes, min(TEST_COUNT,2**block_size))
			for p in strs:
				c = fnr._str_to_bytes(p)
				# check correct type
				self.assertEqual(type(c), bytearray)
				# check correct block size
				self.assertEqual(len(c), block_size_bytes)
				p2 = fnr._bytes_to_str(c)
				# check correct conversion back to int
				self.assertEqual(p, p2)

class TestSalt(unittest.TestCase):

	def test_salt_length(self):
		for i in range(TEST_COUNT):
			salt = pyFNR.generate_salt()
			self.assertEqual(len(salt), pyFNR.SALT_SIZE)

	def test_salt_diversity(self):
		salts = [pyFNR.generate_salt() for i in range(10 * TEST_COUNT)]
		salts.sort()
		for i in range(len(salts)-1):
			self.assertNotEqual(salts[i], salts[i+1])

class TestFNRCrypt(unittest.TestCase):

	def setUp(self):
		# prepare one instance for each block_size
		self.fnr = [(i, pyFNR.FNR(block_size=i)) for i in range(1, 129)]

	def tearDown(self):
		for fnr in self.fnr:
			fnr[1].close()

	def test_encryption_and_decryption_random_raw(self):
		identity = 0
		nonidentity = 0
		for item in self.fnr:
			block_size = item[0]
			# compute number of bytes for block_size in bits
			block_size_bytes = int(math.ceil(block_size*1.0/8))
			fnr = item[1]
			# choose up to TEST_COUNT random raws for encryption
			raws = Helper.generate_random_raw(block_size, min(TEST_COUNT,2**block_size))
			for p in raws:
				c = ctypes.create_string_buffer(block_size_bytes)
				fnr.encrypt_raw(p, c)
				# check correct type
				self.assertEqual(type(c), type(p))
				# count identity
				if (p.raw == c.raw):
					identity += 1
				else:
					nonidentity += 1
				# check correct block size
				self.assertEqual(len(c), block_size_bytes)
				# check correct mask of last byte
				mask = 2**(block_size % 8) - 1 if (block_size % 8) else 0xff
				last_byte = ord(c[-1])
				self.assertEqual(last_byte & ~mask, 0)
				p2 = ctypes.create_string_buffer(block_size_bytes)
				fnr.decrypt_raw(c, p2)
				# check correct decryption
				self.assertEqual(p.raw, p2.raw)
		# check nonidentity transformation
		self.assertEqual(nonidentity > 9*identity, True)

	def test_encryption_and_decryption_random_bytes(self):
		identity = 0
		nonidentity = 0
		for item in self.fnr:
			block_size = item[0]
			# compute number of bytes for block_size in bits
			block_size_bytes = int(math.ceil(block_size*1.0/8))
			fnr = item[1]
			# choose up to TEST_COUNT random bytearrays for encryption
			bytearrays = Helper.generate_random_bytearrays(block_size, min(TEST_COUNT,2**block_size))
			for p in bytearrays:
				c = fnr.encrypt_bytes(p)
				# check correct type
				self.assertEqual(type(c), bytearray)
				# count identity
				if (p == c):
					identity += 1
				else:
					nonidentity += 1
				# check correct block size
				self.assertEqual(len(c), block_size_bytes)
				# check correct mask of last byte
				mask = 2**(block_size % 8) - 1 if (block_size % 8) else 0xff
				last_byte = c[-1]
				self.assertEqual(last_byte & ~mask, 0)
				p2 = fnr.decrypt_bytes(c)
				# check correct decryption
				self.assertEqual(p, p2)
		# check nonidentity transformation
		self.assertEqual(nonidentity > 9*identity, True)

	def test_encryption_and_decryption_random_strings_strip(self):
		identity = 0
		nonidentity = 0
		for item in self.fnr:
			block_size = item[0]
			# compute number of bytes for block_size in bits
			block_size_bytes = int(math.ceil(block_size*1.0/8))
			fnr = item[1]
			# choose up to TEST_COUNT random strings for encryption
			strs = Helper.generate_random_strings(block_size_bytes, min(TEST_COUNT,2**block_size))
			for p in strs:
				mask = 2**(block_size % 8) - 1 if (block_size % 8) else 0xff
				# mask last char of string and strips
				p = p[:-1] + chr(ord(p[-1]) & mask).rstrip('\0')
				c = fnr.encrypt_str(p)
				# check correct type
				self.assertEqual(type(c), str)
				# count identity
				if (p == c):
					identity += 1
				else:
					nonidentity += 1
				# check correct block size
				self.assertEqual(len(c) <= block_size_bytes, True)
				# check correct mask of last byte
				last_byte = ord(c[-1]) if (len(c) == block_size_bytes) else 0
				self.assertEqual(last_byte & ~mask, 0)
				p2 = fnr.decrypt_str(c)
				# check correct decryption
				self.assertEqual(p, p2)
		# check nonidentity transformation
		self.assertEqual(nonidentity > 9*identity, True)

	def test_encryption_and_decryption_random_strings_nostrip(self):
		identity = 0
		nonidentity = 0
		for item in self.fnr:
			block_size = item[0]
			# compute number of bytes for block_size in bits
			block_size_bytes = int(math.ceil(block_size*1.0/8))
			fnr = item[1]
			# choose up to TEST_COUNT random strings for encryption
			strs = Helper.generate_random_strings(block_size_bytes, min(TEST_COUNT,2**block_size))
			for p in strs:
				mask = 2**(block_size % 8) - 1 if (block_size % 8) else 0xff
				# mask last char of string
				p = p[:-1] + chr(ord(p[-1]) & mask)
				c = fnr.encrypt_str(p, strip=False)
				# check correct type
				self.assertEqual(type(c), str)
				# count identity
				if (p == c):
					identity += 1
				else:
					nonidentity += 1
				# check correct block size
				self.assertEqual(len(c), block_size_bytes)
				# check correct mask of last byte
				last_byte = ord(c[-1]) if (len(c) == block_size_bytes) else 0
				self.assertEqual(last_byte & ~mask, 0)
				p2 = fnr.decrypt_str(c, strip=False)
				# check correct decryption
				self.assertEqual(p, p2)
		# check nonidentity transformation
		self.assertEqual(nonidentity > 9*identity, True)

	def test_encryption_and_decryption_random_integers(self):
		identity = 0
		nonidentity = 0
		for item in self.fnr:
			block_size = item[0]
			# compute number of bytes for block_size in bits
			block_size_bytes = int(math.ceil(block_size*1.0/8))
			fnr = item[1]
			# choose up to TEST_COUNT random ints for encryption
			ints = Helper.generate_random_ints(0, 2**block_size, min(TEST_COUNT,2**block_size))
			for p in ints:
				c = fnr.encrypt_int(p)
				# count identity
				if (p == c):
					identity += 1
				else:
					nonidentity += 1
				# check correct format
				self.assertEqual(c < 2**block_size, True)
				# check correct decryption
				p2 = fnr.decrypt_int(c)
				self.assertEqual(p, p2)
		# check nonidentity transformation
		self.assertEqual(nonidentity > 9*identity, True)

class TestFNR2Crypt(unittest.TestCase):

	def setUp(self):
		# prepare one instance for 100 random domains
		domains = Helper.generate_random_ints(0, 2**128, 100)
		self.fnr2 = [(i, pyFNR.FNR2(domain=i)) for i in domains]

	def tearDown(self):
		for fnr2 in self.fnr2:
			fnr2[1].close()

	def test_encryption_and_decryption_random_integers(self):
		identity = 0
		nonidentity = 0
		for item in self.fnr2:
			domain = item[0]
			fnr2 = item[1]
			# choose up to TEST_COUNT random ints for encryption
			ints = Helper.generate_random_ints(0, domain+1, min(TEST_COUNT,domain))
			for p in ints:
				c = fnr2.encrypt(p)
				# count identity
				if (p == c):
					identity += 1
				else:
					nonidentity += 1
				# check correct format
				self.assertEqual(c <= domain, True)
				# check correct decryption
				p2 = fnr2.decrypt(c)
				self.assertEqual(p, p2)
		# check nonidentity transformation
		self.assertEqual(nonidentity > 9*identity, True)

class Helper(object):

	@staticmethod
	def generate_random_bytearrays(bits, count):
		bytes = int(math.floor((bits) * 1.0 / 8)) 
		return [bytearray([random.randint(0,255) for i in range(bytes)] + ([random.randrange(0,2**(bits%8))] if bits % 8 else [])) for w in range(count)]

	@staticmethod
	def generate_random_ints(start, stop, count):
		return [random.randrange(start, stop) for i in range(count)]

	@staticmethod
	def generate_random_strings(length, count):
		return ["".join(random.choice(string.printable) for i in range(length)) for i in range(count)]

	@staticmethod
	def generate_random_raw(bits, count):
		bytearrays = Helper.generate_random_bytearrays(bits, count)
		bytes = int(math.ceil((bits) * 1.0 / 8)) 
		ctype_array = ctypes.c_char * bytes
		return [ctype_array.from_buffer(b) for b in bytearrays]
		

if __name__ == '__main__':
	unittest.main()
