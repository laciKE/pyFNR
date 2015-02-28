import ctypes
import math

libfnr = ctypes.cdll.LoadLibrary('libfnr.so')
libssl = ctypes.cdll.LoadLibrary('libssl.so')

class FNR_expanded_tweak(ctypes.Structure):
	_fields_ = [("tweak", ctypes.c_ubyte * 15)] 

class FNR(object):
	KEY_SIZE = 32 #bytes
	SALT_SIZE = 32 #bytes
	block_size = 32 # bits
	block_size_bytes = 4
	fnr_expanded_key = None
	fnr_tweak = FNR_expanded_tweak()

	#block_size: bites
	def __init__(self, password="0000000000000000", tweak="tweak-is-string", block_size=32, salt="\0" * SALT_SIZE):
		self.block_size = block_size
		self.block_size_bytes = int(math.ceil(1.0 * self.block_size / 8))

		master_key = "\0" * self.KEY_SIZE
		if (libssl.PKCS5_PBKDF2_HMAC_SHA1(password, len(password), salt, self.SALT_SIZE, 1000, self.KEY_SIZE, master_key) != 1):
			raise EnvironmentError("call to OpenSSL's PKCS5_PBKDF2_HMAC_SHA1 failed")

		libfnr.FNR_init()
		self.fnr_expanded_key = libfnr.FNR_expand_key(master_key, self.KEY_SIZE*8, block_size)
		if (not self.fnr_expanded_key):
			raise EnvironmentError("call to fnr_expanded_key failed")

		libfnr.FNR_expand_tweak(ctypes.byref(self.fnr_tweak), self.fnr_expanded_key, tweak, len(tweak))

	def close(self):
		libfnr.FNR_release_key(self.fnr_expanded_key)
		libfnr.FNR_shut()

	def encrypt_str(self, plaintext):
		raw_plaintext = ctypes.create_string_buffer(plaintext, self.block_size_bytes)
		raw_ciphertext = ctypes.create_string_buffer(self.block_size_bytes)

		libfnr.FNR_encrypt(self.fnr_expanded_key, ctypes.byref(self.fnr_tweak), raw_plaintext, raw_ciphertext)

		return raw_ciphertext.raw

	def decrypt_str(self, ciphertext, strip=True):
		raw_plaintext = ctypes.create_string_buffer(self.block_size_bytes)
		raw_ciphertext = ctypes.create_string_buffer(ciphertext, self.block_size_bytes)

		libfnr.FNR_decrypt(self.fnr_expanded_key, ctypes.byref(self.fnr_tweak), raw_ciphertext, raw_plaintext)
		plaintext = raw_plaintext.raw.strip('\0') if strip else raw_plaintext.raw

		return plaintext

	def encrypt_int(self, plaintext):
		ciphertext = self.encrypt_str(self._int_to_str(plaintext))

		return self._str_to_int(ciphertext)

	def decrypt_int(self, ciphertext):
		plaintext = self.decrypt_str(self._int_to_str(ciphertext), strip=False)

		return self._str_to_int(plaintext)

	def generate_salt(self):
		salt = "\0" * self.SALT_SIZE
		if (libssl.RAND_bytes(salt, 32) != 1 ):
			raise EnvironmentError("call to OpenSSL's RAND_bytes failed")
		return salt

	def _int_to_str(self, intval):
		hexval = "{0:x}".format(intval)
		# even number of chars, each byte should be two chars
		if (len(hexval) % 2):
			hexval = "0" + hexval
		try:
			strval = str(bytearray.fromhex(hexval))
		except TypeError:
			# workaround for Python 2.6 unicode requirement
			strval = str(bytearray.fromhex(unicode(hexval)))

		return strval

	def _str_to_int(self, strval):
		return int(strval.encode("hex"), 16)
