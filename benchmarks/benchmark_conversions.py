import time
import random
import pyFNR

N_SAMPLES = 100000
salt=""
s = 128
fnr = pyFNR.FNR(key="password", tweak="string tweak", salt=salt, block_size=s)

i_tests = [random.randint(0,2**s-1) for _ in range(N_SAMPLES)]
b_tests = [fnr._int_to_bytes(i) for i in i_tests]


start = time.time()
for i in i_tests:
	b = fnr._int_to_bytes(i)
end = time.time()
print("_int_to_bytes : " + str((end-start)*1000/len(i_tests)) + "ms")

start = time.time()
for i in i_tests:
	b = fnr._int_to_bytes2(i)
end = time.time()
print("_int_to_bytes2: " + str((end-start)*1000/len(i_tests)) + "ms")

start = time.time()
for i in b_tests:
	b = fnr._bytes_to_int(i)
end = time.time()
print("_bytes_to_int : " + str((end-start)*1000/len(b_tests)) + "ms")

start = time.time()
for i in b_tests:
	b = fnr._bytes_to_int2(i)
end = time.time()
print("_bytes_to_int2: " + str((end-start)*1000/len(b_tests)) + "ms")

start = time.time()
for i in b_tests:
	b = fnr.encrypt_bytes(i)
end = time.time()
print("encrypt_bytes : " + str((end-start)*1000/len(b_tests)) + "ms")

start = time.time()
for i in b_tests:
	b = fnr.decrypt_bytes(i)
end = time.time()
print("decrypt_bytes : " + str((end-start)*1000/len(b_tests)) + "ms")

fnr.close()
