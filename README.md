Python bindings for libFNR from Cisco: https://github.com/cisco/libfnr

This module currently provides two classes:
* FNR: libFNR wrapper with methods for enciphering/deciphering strings, integers, bytearrays and raw c_char_Arrays. 
* FNR2: FNR wrapper with cycle walking method for extending FNR enciphering scheme to all size of domains < 2^128, not only for sizes which are powers of two (2^block_size).

IMPORTANT: This is an experimental module and uses experimental cipher, not for production yet.

Some benchmarks and performance improvements will be done during March and April 2015.