import time
import random
import pyFNR

N_SAMPLES = 10000
salt = pyFNR.generate_salt()

for s in range(2, 128):
	tests = [random.randint(0,2**s-1) for _ in range(10000)]
	fnr = pyFNR.FNR(key="password", tweak="string tweak", salt=salt, block_size=s)

	start = time.time()
	for p in tests:
		c = fnr.encrypt_int(p)
		p2 = fnr.decrypt_int(c)
		#if p != p2:
		#	print(str(p) + '\t' + str(c) + '\t' + str(p2))
	end = time.time()
	print('block_size:' + str(s).rjust(3) + '\tencryption/decryption average time: ' + str((end-start)*1000/2/len(tests)) + "ms")

fnr.close()
