import random
import hashlib
from sympy import isprime, primerange


class Generator:
    def __init__(self):
       pass


    def find_generator(self,p):

        factors = list(primerange(2, p))
        p_minus_1 = p - 1
        factor_set = [f for f in factors if p_minus_1 % f == 0]

        for g in range(2, p):
            valid = True
            for factor in factor_set:
                if pow(g, (p - 1) // factor, p) == 1:
                    valid = False
                    break
            if valid:
                return g
        return None

class DigitalSignature:

    def __init__(self,p,g):
        self.p = p
        self.g = g
        self.private_key = None
        self.public_key = None




    def hash_message(self, message):
        # Hash the message using SHA-256 and convert to an integer
        # hashed = int(hashlib.sha256(message.encode()).hexdigest(), 16)
        hashed_message = hashlib.sha256(str(message).encode()).hexdigest()
        hashed= int(hashed_message, 16)
        return hashed % self.p

    def gcd(self, a, b):
        while b != 0:
            a, b = b, a % b
        return a

    def mod_exp(self, base, exp, mod):
        result = 1
        base = base % mod
        while exp > 0:
            if exp % 2 == 1:
                result = (result * base) % mod
            exp = exp >> 1
            base = (base * base) % mod
        return result

    def mod_inverse(self, a, mod):
        for x in range(1, mod):
            if (a * x) % mod == 1:
                return x
        return -1

    def key_generation(self):

        self.private_key = random.randint(1, self.p - 1)
        self.public_key = self.mod_exp(self.g, self.private_key, self.p)


    def sign_message(self, message):
        hashed_message = self.hash_message(message)
        k = None
        while True:
            k = random.randint(1, self.p - 2)
            if self.gcd(k, self.p - 1) == 1:
                break

        r = self.mod_exp(self.g, k, self.p)
        k_inverse = self.mod_inverse(k, self.p - 1)
        s = (k_inverse * (hashed_message - self.private_key * r)) % (self.p - 1)
        if s < 0:
            s += (self.p - 1)

        return r, s

    def verify_signature(self, message, r, s):
        if r <= 0 or r >= self.p:
            return False
        hashed_message = self.hash_message(message)
        v1 = (self.mod_exp(self.public_key, r, self.p) * self.mod_exp(r, s, self.p)) % self.p
        v2 = self.mod_exp(self.g, hashed_message, self.p)
        return v1 == v2


# Example Usage
if __name__ == "__main__":
    generator = Generator()
    p= 467 #choose big number
    g= generator.find_generator(p)
    ds = DigitalSignature(p,g)
    ds.key_generation()
    message = "hello world"

    r, s = ds.sign_message(message)
    print(f"Message: {message}")
    print(f"Signature: (r={r}, s={s})")

    is_valid = ds.verify_signature(message, r, s)
    print(f"Signature valid: {is_valid}")
