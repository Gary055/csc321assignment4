from random import randint
from Crypto.Hash import SHA256
from operator import xor
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import hashlib
import random
import binascii
import time
import matplotlib.pyplot as plt

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
    modified = flip_bit(base, bit_to_flip)
    h1 = out_hash_256(base)
    h2 = out_hash_256(modified)
    print(f"Example {i+1}: flipped bit #{bit_to_flip}")
    print(f"Base    ({binascii.hexlify(base).decode()}): {h1}")
    print(f"Modified({binascii.hexlify(modified).decode()}): {h2}\n")

def truncate(digest : bytes, seg : int):
    dig_int = int.from_bytes(digest, 'big')
    return dig_int & ((1 << seg) - 1)

def birthday_attack(domain : int, tries_limit : int = 10000000):
    table = {}
    for i in range(int(tries_limit)):
        msg = i.to_bytes(8, 'big') + os.urandom(8)
        dig = hashlib.sha256(msg).digest()
        tru = truncate(dig, domain)
        if tru in table:
            other = table[tru]
            if other != msg:
                return other, msg, tru, i+1
        else:
            table[tru] = msg
    return None

results = {}
for i in range(8, 52, 2):
    start = time.time()
    expected = 4 * (2 ** (i / 2))
    fir, sec, te, tries = birthday_attack(i, max(expected, 10000000))
    tot = time.time() - start
    print(f"Collision iteration {i} bits in {tries} tries, time {tot}")
    print(f"M1: {fir}")
    print(f"M2: {sec}")
    print(f"Truncated: {te}")
    results[i] = (fir, sec, te, tries)

keys = results.keys()
values = results.values()
st_1, st_2 = [], []
for i in values:
    st_1.append(i[2])
    st_2.append(i[3])
plt.plot(keys, st_1)
plt.savefig('digest_vs_inputs.png')
plt.plot(keys, st_2)
plt.savefig('digest_vs_time.png')