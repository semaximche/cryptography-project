class Kuznechik:
    # kuznechik's pi s-boxes as specified
    PI = [252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
          233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
          249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79,
          5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31,
          235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204,
          181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135,
          21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
          50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87,
          223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3,
          224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74,
          167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
          173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59,
          7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137,
          225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
          32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82,
          89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182]

    INV_PI = [165, 45, 50, 143, 14, 48, 56, 192, 84, 230, 158, 57, 85, 126, 82, 145,
              100, 3, 87, 90, 28, 96, 7, 24, 33, 114, 168, 209, 41, 198, 164, 63,
              224, 39, 141, 12, 130, 234, 174, 180, 154, 99, 73, 229, 66, 228, 21, 183,
              200, 6, 112, 157, 65, 117, 25, 201, 170, 252, 77, 191, 42, 115, 132, 213,
              195, 175, 43, 134, 167, 177, 178, 91, 70, 211, 159, 253, 212, 15, 156, 47,
              155, 67, 239, 217, 121, 182, 83, 127, 193, 240, 35, 231, 37, 94, 181, 30,
              162, 223, 166, 254, 172, 34, 249, 226, 74, 188, 53, 202, 238, 120, 5, 107,
              81, 225, 89, 163, 242, 113, 86, 17, 106, 137, 148, 101, 140, 187, 119, 60,
              123, 40, 171, 210, 49, 222, 196, 95, 204, 207, 118, 44, 184, 216, 46, 54,
              219, 105, 179, 20, 149, 190, 98, 161, 59, 22, 102, 233, 92, 108, 109, 173,
              55, 97, 75, 185, 227, 186, 241, 160, 133, 131, 218, 71, 197, 176, 51, 250,
              150, 111, 110, 194, 246, 80, 255, 93, 169, 142, 23, 27, 151, 125, 236, 88,
              247, 31, 251, 124, 9, 13, 122, 103, 69, 135, 220, 232, 79, 29, 78, 4,
              235, 248, 243, 62, 61, 189, 138, 136, 221, 205, 11, 19, 152, 2, 147, 128,
              144, 208, 36, 52, 203, 237, 244, 206, 153, 16, 68, 64, 146, 58, 1, 38,
              18, 26, 72, 104, 245, 129, 139, 199, 214, 32, 10, 8, 0, 76, 215, 116]

    # kuznechik vector of polynomials to multiply by when performing the linear transformation
    LIN_VEC = [148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1]

    @staticmethod
    def count_bits(integer):
        """"Counts the number of bits in integer"""
        bits = 0
        while integer != 0:
            bits += 1
            integer >>= 1
        return bits

    @staticmethod
    def gf2_mult(p1, p2):
        """Multiples two binary polynomials p1 and p2 over gf2
        returns p1(x) * p2(x)
        """
        if p1 == 0 or p2 == 0:
            return 0
        p = 0
        while p1:
            if p1 & 1:
                p ^= p2
            p2 <<= 1
            p1 >>= 1
        return p

    @staticmethod
    def gf2_mod(p, m):
        """Mods binary polynomial p by m
        returns p(x) mod m(x)
        """
        bits_m = Kuznechik.count_bits(m)
        while True:
            bits_p = Kuznechik.count_bits(p)
            if bits_p < bits_m:
                return p
            mod_shift = m << (bits_p - bits_m)
            p ^= mod_shift

    """Non Linear Transformation Functions"""

    @staticmethod
    def sub_bytes(ibytes):
        """s-box function
        input 128 bit divided into 16 sections of 8 bits to apply s-box on
        output 128-bit substituted output
        """
        subbed_bytes = 0
        for i in reversed(range(16)):
            subbed_bytes <<= 8
            subbed_bytes += Kuznechik.PI[ibytes >> (8 * i) & 0xff]
        return subbed_bytes

    @staticmethod
    def inv_sub_bytes(ibytes):
        """inverse s-box function
        input substituted 128 bit to apply inverse s-box on
        output 128-bit output
        """
        subbed_bytes = 0
        for i in reversed(range(16)):
            subbed_bytes <<= 8
            subbed_bytes += Kuznechik.INV_PI[ibytes >> (8 * i) & 0xff]
        return subbed_bytes

    """Linear Transformation Functions"""

    @staticmethod
    def mult_mod(p1, p2):
        """kuz variation of multiplication using mod p(x) = x^8 + x^7 + x^6 + x + 1 (111000011)
        input 8-bit ints representing binary polynomials p1(x), p2(x)
        returns p1(x) * p2(x) mod p(x)
        """
        p = Kuznechik.gf2_mult(p1, p2)
        return Kuznechik.gf2_mod(p, int('111000011', 2))

    @staticmethod
    def lin_func(a):
        """linear transformation of kuz
        input 128-bit divided into 16 sections
        output multiplication between the 16 input sections and predefined mult array
        """
        mult_arr = Kuznechik.LIN_VEC.copy()
        y = 0
        while a != 0:
            y ^= Kuznechik.mult_mod(a & 0xff, mult_arr.pop())
            a >>= 8
        return y

    @staticmethod
    def r_func(a):
        """R function from the kuz algorithm
        inputs 128-bit
        applies the kuz linear function multiplication and puts it as the 8 most significant bits xor input itself
        performing this 16 times gives us the linear function multiplication over the whole 128 bits
        """
        return (Kuznechik.lin_func(a) << 120) ^ (a >> 8)

    @staticmethod
    def inv_r_func(a):
        """R inverse function from the kuz algorithm"""
        a2 = a >> 120
        a = (a << 8) & (2 ** 128 - 1)
        return Kuznechik.lin_func(a ^ a2) ^ a

    @staticmethod
    def l_func(a):
        """L function from the kuz algorithm
        repeats the r function 16 times over input
        """
        for i in range(16):
            a = Kuznechik.r_func(a)
        return a

    @staticmethod
    def inv_l_func(a):
        """L inverse function from the kuz algorithm
        repeats the r function 16 times over input
        """
        for i in range(16):
            a = Kuznechik.inv_r_func(a)
        return a

    """Encryption Algorithm"""

    @staticmethod
    def f_func(a1, a2, c):
        """f function from the kuz algorithm
        a1, a2 are keys and c is a constant
        runs the substitution and linear transform for keys generation
        returns a tuple of keys"""
        return Kuznechik.l_func(Kuznechik.sub_bytes(a1 ^ c)) ^ a2, a1

    @staticmethod
    def key_generator(key):
        """k is 256-bits
        The key generation algorithm returns 10 keys of 128-bits each
        """
        keys = []

        # first key is the 128 most significant bits of k
        k1 = key >> 128

        # second key is 128 least bit of k
        k2 = key & (2 ** 128 - 1)
        keys.append(k1)
        keys.append(k2)

        # other keys are derived from the kuz linear function over 1..32
        c = []
        for i in range(32):
            c.append(Kuznechik.l_func(i + 1))

        # keys generated in pairs from kuz f function
        for i in range(4):
            # iterate over 8 pairs and then add to keys list
            for j in range(8):
                (k1, k2) = Kuznechik.f_func(k1, k2, c[8 * i + j])
            keys.append(k1)
            keys.append(k2)

        return keys

    @staticmethod
    def encrypt_block(block, key):
        """The plain data block is 128-bits
        Key is 256-bits
        """
        kuz_keys = Kuznechik.key_generator(key)
        for i in range(9):
            block = Kuznechik.sub_bytes(block ^ kuz_keys[i])
            block = Kuznechik.l_func(block)
        return block ^ kuz_keys[-1]

    @staticmethod
    def decrypt_block(block, key):
        """The cipher data block is 128-bits
        Key is 256-bits
        """
        kuz_keys = Kuznechik.key_generator(key)
        kuz_keys.reverse()
        for i in range(9):
            block = Kuznechik.inv_l_func(block ^ kuz_keys[i])
            block = Kuznechik.inv_sub_bytes(block)
        return block ^ kuz_keys[-1]

    @staticmethod
    def encrypt(data, key):
        """Plain data is any utf-8 string to encrypt
        Key is 256-bits
        Returns encrypted hex string
        """
        # if data is string encode as bytes array
        if type(data) is str:
            data = data.encode('utf-8')

        # add padding
        while len(data) % 16 != 0:
            data += ' '.encode('utf-8')

        # plaintext blocks construction
        pt_blocks = []
        for i in range(0, len(data), 16):
            pt_blocks.append(int.from_bytes(data[i:i + 16], 'big'))

        # ciphertext blocks encryption
        ct_blocks = []
        encrypted = ""
        for i in range(len(pt_blocks)):
            ct_blocks.append(Kuznechik.encrypt_block(pt_blocks[i], key))
            encrypted += f'{ct_blocks[i]:x}'

        return encrypted

    @staticmethod
    def decrypt(data, key):
        # ciphertext blocks construction
        data = data.encode('utf-8')
        block_size = 32
        ct_blocks = []
        for i in range(0, len(data), block_size):
            ct_blocks.append(int(data[i:i + block_size], 16))

        # ciphertext blocks decryption and decoding
        dt_blocks = []
        decoded = ""
        for i in range(len(ct_blocks)):
            dt_blocks.append(Kuznechik.decrypt_block(ct_blocks[i], key))
            decoded += dt_blocks[i].to_bytes(16, 'big').decode('utf-8')

        return decoded


if __name__ == "__main__":
    # plaintext
    plaintext = ("Dear reader, this is a heartfelt email sent to you encrypted and signed in the most "
                 "secure manner possible. This message uses asymmetric ECDH key exchange so that we "
                 "will both have the same shared key for when you open and read this message. The message "
                 "itself was encrypted using the symmetric Kuznechik encryption algorithm. And finally, "
                 "I signed this message with an El Gamal signature so that you know you're receiving "
                 "this message from me and not anyone else. Thanks for reading, yours truly, the writer.")

    # key
    shared_key = int('8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef', 16)

    ciphertext = Kuznechik.encrypt(plaintext, shared_key)
    print('REAL encrypted:', ciphertext)
    decrypted = Kuznechik.decrypt(ciphertext, shared_key)
    print('REAL decrypted:', decrypted)