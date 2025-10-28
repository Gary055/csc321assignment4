from random import randint
from Crypto.Hash import SHA256
from operator import xor
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import hashlib
import random
import binascii

def out_hash_256(input : bytes) -> None:
    # byt = input.encode('utf-8')
    # obj = hashlib.sha3_256(byt)

    obj = hashlib.sha3_256(input)
    dig = obj.hexdigest()
    # print(dig)
    return dig

data_list = [b"hello bill", b"", b"mineshaft"]
for i in data_list:
    print("SHA256 Example: " + out_hash_256(i))

print()

def flip_bit(b: bytes, bit_index: int) -> bytes:
    ba = bytearray(b)
    byte_idx = bit_index // 8
    bit_in_byte = bit_index % 8
    ba[byte_idx] ^= (1 << bit_in_byte)
    return bytes(ba)


base = os.urandom(16)
for i in range(10):
    bit_to_flip = random.randrange(0, len(base) * 8)
    altered = flip_bit(base, bit_to_flip)
    h1 = out_hash_256(base)
    h2 = out_hash_256(altered)
    print(f"Example {i+1}: flipped bit #{bit_to_flip}")
    print(f" Base   ({binascii.hexlify(base).decode()}): {h1}")
    print(f" Altered({binascii.hexlify(altered).decode()}): {h2}\n")