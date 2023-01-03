#!/usr/bin/env python3

from bloomfilter import BloomFilter, BIP37_CONSTANT
from helper import bit_field_to_bytes, murmur3

field_size = 10
function_count = 5
tweak = 99
items = (b'Hello World',  b'Goodbye!')
bitfield_size = field_size * 8
bit_field = [0] * bitfield_size
for phrase in items:
    for i in range (function_count):
        seed = i * BIP37_CONSTANT + tweak
        h = murmur3(phrase, seed=seed)
        bit = h % bitfield_size
        bit_field[bit] = 1
print(bit_field_to_bytes(bit_field).hex())