import ctypes
import math

libfnr = ctypes.cdll.LoadLibrary('libfnr.so')
libssl = ctypes.cdll.LoadLibrary('libssl.so')

KEY_SIZE = 32 #bytes
SALT_SIZE = 32 #bytes

class FNR_expanded_tweak(ctypes.Structure):
	_fields_ = [("tweak", ctypes.c_ubyte * 15)] 

class FNR(object):
	block_size = 32 # bits
	block_size_bytes = 4
	raw_type = ctypes.c_char*block_size_bytes

	fnr_expanded_key = None
	fnr_tweak = FNR_expanded_tweak()
	#fnr_tweak = ctypes.create_string_buffer(15)


	#block_size: bites
	def __init__(self, password="0000000000000000", tweak="tweak-is-string", block_size=32, salt=""):
		self.block_size = block_size
		self.block_size_bytes = int(math.ceil(1.0 * self.block_size / 8))
		self.raw_type = ctypes.c_char*self.block_size_bytes

		master_key = ctypes.create_string_buffer(KEY_SIZE)
		raw_password = ctypes.create_string_buffer(password)
		raw_salt = ctypes.create_string_buffer(salt, SALT_SIZE)
		raw_tweak = ctypes.create_string_buffer(tweak)

		if (libssl.PKCS5_PBKDF2_HMAC_SHA1(raw_password, len(raw_password), raw_salt, SALT_SIZE, 1000, KEY_SIZE, master_key) != 1):
			raise EnvironmentError("call to OpenSSL's PKCS5_PBKDF2_HMAC_SHA1 failed")

		libfnr.FNR_init()
		self.fnr_expanded_key = libfnr.FNR_expand_key(master_key, KEY_SIZE*8, block_size)
		if (not self.fnr_expanded_key):
			raise EnvironmentError("call to fnr_expanded_key failed")

		libfnr.FNR_expand_tweak(ctypes.byref(self.fnr_tweak), self.fnr_expanded_key, raw_tweak, len(raw_tweak))


	def close(self):
		libfnr.FNR_release_key(self.fnr_expanded_key)
		libfnr.FNR_shut()

	# plaintext: bytearray
	def encrypt_bytes(self, plaintext):
		raw_plaintext = self.raw_type.from_buffer(plaintext)
		raw_ciphertext = ctypes.create_string_buffer(self.block_size_bytes)

		libfnr.FNR_encrypt(self.fnr_expanded_key, ctypes.byref(self.fnr_tweak), raw_plaintext, raw_ciphertext)

		return bytearray(raw_ciphertext.raw)

	# ciphertext: bytearray
	def decrypt_bytes(self, ciphertext):
		raw_plaintext = ctypes.create_string_buffer(self.block_size_bytes)
		raw_ciphertext = self.raw_type.from_buffer(ciphertext)

		libfnr.FNR_decrypt(self.fnr_expanded_key, ctypes.byref(self.fnr_tweak), raw_ciphertext, raw_plaintext)

		return bytearray(raw_plaintext.raw)

	def encrypt_str(self, plaintext, strip=True):
		padded_plaintext = plaintext + '\x00' * (self.block_size_bytes - len(plaintext))
		bytes_plaintext = self._str_to_bytes(padded_plaintext)
		bytes_ciphertext = self.encrypt_bytes(bytes_plaintext)
		padded_ciphertext = self._bytes_to_str(bytes_ciphertext)
		ciphertext= padded_ciphertext.strip('\x00') if strip else padded_ciphertext

		return ciphertext

	def decrypt_str(self, ciphertext, strip=True):
		padded_ciphertext = ciphertext + '\x00' * (self.block_size_bytes - len(ciphertext))
		bytes_ciphertext = self._str_to_bytes(padded_ciphertext)
		bytes_plaintext = self.decrypt_bytes(bytes_ciphertext)
		padded_plaintext = self._bytes_to_str(bytes_plaintext)
		plaintext = padded_plaintext.strip('\x00') if strip else padded_plaintext

		return plaintext

	def encrypt_int(self, plaintext):
		ciphertext = self.encrypt_bytes(self._int_to_bytes(plaintext))
		return self._bytes_to_int(ciphertext)


	def decrypt_int(self, ciphertext):
		plaintext = self.decrypt_bytes(self._int_to_bytes(ciphertext))

		return self._bytes_to_int(plaintext)

	def _str_to_bytes(self, strval):
		return bytearray([ord(x) for x in strval])

	def _bytes_to_str(self, bytesval):
		return "".join(map(chr, bytesval))

	def _int_to_bytes2(self, intval):
		hexval = "{0:x}".format(intval)
		hexval = "0"*(self.block_size_bytes*2 - len(hexval)) + hexval # padding with 0s 
		try:
			bytesval = bytearray.fromhex(hexval)
		except TypeError:
			# workaround for Python 2.6 unicode requirement
			bytesval = bytearray.fromhex(unicode(hexval))	
		bytesval.reverse() # little endian

		return bytesval

	def _int_to_bytes(self, intval):
		bytelist = [(intval & (0xff << 8*byte)) >> 8*byte for byte in range(self.block_size_bytes)]
		return bytearray(bytelist)

	def _bytes_to_int2(self, bytesval):
		bytesval_copy = bytearray(bytesval)
		bytesval_copy.reverse() # little endian
		strval = self._bytes_to_str(bytesval_copy)
		return int(strval.encode("hex"), 16)

	def _bytes_to_int(self, bytesval):
		intval = 0
		for byte in range(self.block_size_bytes):
			intval *= 0x100
			intval += bytesval[self.block_size_bytes-byte-1]
		return intval

def generate_salt():
	salt = ctypes.create_string_buffer(SALT_SIZE)
	if (libssl.RAND_bytes(salt, SALT_SIZE) != 1 ):
		raise EnvironmentError("call to OpenSSL's RAND_bytes failed")
	return salt.raw
