Python bindings for libFNR from Cisco: https://github.com/cisco/libfnr

This library currently support Python2.6 to Python3.4 and provides two classes:
* FNR: libFNR wrapper with methods for enciphering/deciphering strings, integers, bytearrays and raw c_char_Arrays. 
* FNR2: FNR wrapper with cycle walking method for extending FNR enciphering scheme to all size of domains < 2^128, not only for sizes which are powers of two (2^block_size).

IMPORTANT: This is an experimental module and uses experimental cipher, not for production yet.



Note: due to benchmarks on Python3.2 and newer it seems that native `int.to_bytes()` is slower than `bytearray.fromhex()` method, so I choose later method instead of former.

some benchmarks: (average time of 100.000 calls)
with `int.to_bytes()`
```
$ python3.4 benchmarks/benchmark_conversions.py 
_int_to_bytes : 0.004318721294403076ms
_int_to_bytes2: 0.013562514781951904ms
_bytes_to_int : 0.0025879740715026855ms
_bytes_to_int2: 0.010645673274993897ms
encrypt_bytes : 0.02397698163986206ms
decrypt_bytes : 0.02381234645843506ms
```
with `bytearray.fromhex()`
```
$ python3.4 benchmarks/benchmark_conversions.py 
_int_to_bytes : 0.0032341837882995605ms
_int_to_bytes2: 0.01392204999923706ms
_bytes_to_int : 0.0027048635482788087ms
_bytes_to_int2: 0.010532338619232178ms
encrypt_bytes : 0.023919179439544677ms
decrypt_bytes : 0.023606929779052734ms
```
