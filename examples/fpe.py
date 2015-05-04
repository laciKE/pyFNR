import pyFNR

salt = pyFNR.generate_salt()
fnr16 = pyFNR.FNR(key='password', tweak='tweak-is-string', block_size=16, salt=salt)
fnr64 = pyFNR.FNR(key='password', tweak='tweak-is-string', block_size=64, salt=salt)

plain_int = 47
cipher_int = fnr16.encrypt_int(plain_int)
plain2_int = fnr16.decrypt_int(cipher_int)
print(str(plain_int) + ' -> ' + str(cipher_int) + ' -> ' + str(plain2_int))

cipher_int = fnr64.encrypt_int(plain_int)
plain2_int = fnr64.decrypt_int(cipher_int)
print(str(plain_int) + ' -> ' + str(cipher_int) + ' -> ' + str(plain2_int))

plain_str = "Hello"
cipher_str = fnr64.encrypt_str(plain_str)
plain2_str = fnr64.decrypt_str(cipher_str)
print(repr(plain_str) + ' -> ' + repr(cipher_str) + ' -> ' + repr(plain2_str))

fnr16.close()
fnr64.close()
