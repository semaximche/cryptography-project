import numpy as np


# -----
# Utils
# -----

# output number of bits of x
def count_bits(x):
    b = 0
    while x != 0:
        b += 1
        x >>= 1
    return b


# input int p1, p2 representing binary polynomials
# output p1(x) * p2(x) over gf2
def gf2_mult(p1, p2):
    if p1 == 0 or p2 == 0:
        return 0
    p = 0
    while p1:
        if p1 & 1:
            p ^= p2
        p2 <<= 1
        p1 >>= 1
    return p


# input p binary polynomial as int
# output p(x) mod m(x)
def gf2_mod(p, m):
    bm = count_bits(m)
    while True:
        bp = count_bits(p)
        if bp < bm:
            return p
        mshift = m << (bp - bm)
        p ^= mshift


# -------------------------
# Non Linear Transformation
# -------------------------

# pi s-boxes array as specified
kuz_pi = [0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16,
          0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
          0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA,
          0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
          0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21,
          0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
          0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0,
          0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
          0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB,
          0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
          0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12,
          0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
          0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7,
          0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
          0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E,
          0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
          0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9,
          0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
          0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC,
          0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
          0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44,
          0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
          0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F,
          0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
          0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7,
          0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
          0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE,
          0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
          0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B,
          0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
          0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0,
          0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6]

# generate inverse pi s-box array
kuz_pi_inverse = [0] * len(kuz_pi)
for i in range(len(kuz_pi)):
    kuz_pi_inverse[kuz_pi[i]] = i


# s-box function
# 128 bit input divided into 16 sections of 8 bits
# s-box is applied to each section
# 128-bit substituted output
def kuz_substitute(a):
    y = 0
    for i in reversed(range(16)):
        y <<= 8
        y += kuz_pi[a >> (8 * i) & 0xff]
    return y


# inverse s-box function
# applies the inverse s-box on 128-bit input
# 128-bit output
def kuz_inverse_substitute(a):
    y = 0
    for i in reversed(range(16)):
        y <<= 8
        y += kuz_pi_inverse[a >> (8 * i) & 0xff]
    return y


# ---------------------
# Linear Transformation
# ---------------------

# kuz variation of multiplication using mod p(x) = x^8 + x^7 + x^6 + x + 1 (111000011)
# input 8-bit ints representing binary polynomials
# output 8-bit
def kuz_mult(p1, p2):
    p = gf2_mult(p1, p2)
    return gf2_mod(p, int('111000011', 2))


# linear transformation of kuz
# input 128-bit divided into 16 sections
# output kuz_mult between the 16 input sections and predefined mult array
def kuz_lin_func(a):
    kuz_mult_arr = [148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1]
    y = 0
    while a != 0:
        y ^= kuz_mult(a & 0xff, kuz_mult_arr.pop())
        a >>= 8
    return y


# R function from the kuz algorithm
# input 8 bit section
# outputs the kuz linear function multiplication xor the input
def kuz_r_func(a):
    kuz_a = kuz_lin_func(a)
    return (kuz_a << 8 * 15) ^ (a >> 8)


# R inverse function from the kuz algorithm
def kuz_inverse_r_func(a):
    a2 = a >> 15 * 8
    a = (a << 8) & (2 ** 128 - 1)
    kuz_a = kuz_lin_func(a ^ a2)
    return a ^ kuz_a


# L function from the kuz algorithm
# repeats the r function over input
def kuz_l_func(a):
    for i in range(16):
        a = kuz_r_func(a)
    return a


# L inverse function from the kuz algorithm
# repeats the r function over input
def kuz_inverse_l_func(a):
    for i in range(16):
        a = kuz_inverse_r_func(a)
    return a


# --------------------
# Encryption Algorithm
# --------------------

# k is 256-bits
# The key schedule algorithm returns 10 keys of 128-bits each
def kuz_key_schedule(k):
    keys = []
    a = k >> 128
    b = k & (2 ** 128 - 1)
    keys.append(a)
    keys.append(b)
    for i in range(4):
        for j in range(8):
            c = kuz_l_func(8 * i + j + 1)
            (a, b) = (kuz_l_func(kuz_substitute(a ^ c)) ^ b, a)
        keys.append(a)
        keys.append(b)
    return keys


# The plaintext x is 128-bits
# The key k is 256-bits
def kuz_encrypt(x, k):
    keys = kuz_key_schedule(k)
    for i in range(9):
        x = kuz_l_func(kuz_substitute(x ^ keys[i]))
    return x ^ keys[-1]


# The ciphertext x is 128-bits
# The key k is 256-bits
def kuz_decrypt(x, k):
    keys = kuz_key_schedule(k)
    keys.reverse()
    for i in range(9):
        x = kuz_inverse_substitute(kuz_inverse_l_func(x ^ keys[i]))
    return x ^ keys[-1]


# plaintext
PT = int('1122334455667700ffeeddccbbaa9988', 16)
print('plaintext: ', hex(PT))

# key
k = int('8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef', 16)
print('key: ', hex(k))

# ciphertext
CT = kuz_encrypt(PT, k)
print('ciphertext: ', hex(CT))

# decrypted text
DT = kuz_decrypt(CT, k)
print('decrypted: ', hex(DT))
