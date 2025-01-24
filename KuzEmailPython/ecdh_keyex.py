import hashlib
from typing import Tuple, Optional
import secrets


class ECDHKeyExchange:
    # Secp256k1 curve parameters
    CURVE_A = 0
    CURVE_B = 7
    # PRIME_MODULUS = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
    PRIME_MODULUS = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    BASE_POINT = (
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    )

    @staticmethod
    def is_on_curve(point: Optional[Tuple[int, int]]) -> bool:
        """Verify if a point lies on the elliptic curve."""
        if point is None:
            return True  # Point at infinity
        x, y = point
        return (y * y - x * x * x - ECDHKeyExchange.CURVE_A * x - ECDHKeyExchange.CURVE_B) % ECDHKeyExchange.PRIME_MODULUS == 0

    @staticmethod
    def point_add(P: Optional[Tuple[int, int]], Q: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
        """Add two points on the elliptic curve."""
        if P is None:
            return Q
        if Q is None:
            return P

        x1, y1 = P
        x2, y2 = Q
        p = ECDHKeyExchange.PRIME_MODULUS

        if x1 == x2:
            if y1 != y2:
                return None  # Points are inverses
            # Point doubling
            if y1 == 0:
                return None
            m = (3 * x1 * x1 + ECDHKeyExchange.CURVE_A) * pow(2 * y1, -1, p)
        else:
            # Point addition
            m = (y2 - y1) * pow(x2 - x1, -1, p)

        x3 = (m * m - x1 - x2) % p
        y3 = (m * (x1 - x3) - y1) % p
        return (x3, y3)

    @staticmethod
    def scalar_mult(k: int, P: Tuple[int, int]) -> Optional[Tuple[int, int]]:
        """Multiply a point by a scalar using double-and-add algorithm."""
        if k == 0 or P is None:
            return None
        Q = None
        while k > 0:
            if k & 1:
                Q = ECDHKeyExchange.point_add(Q, P)
            P = ECDHKeyExchange.point_add(P, P)
            k >>= 1
        return Q

    @staticmethod
    def generate_private_key() -> int:
        """Generate a cryptographically secure private key."""
        return secrets.randbelow(ECDHKeyExchange.CURVE_ORDER - 1) + 1

    @staticmethod
    def derive_public_key(private_key: int) -> Tuple[int, int]:
        """Derive public key from private key."""
        public_key = ECDHKeyExchange.scalar_mult(private_key, ECDHKeyExchange.BASE_POINT)
        if public_key is None:
            raise ValueError("Invalid public key generation")
        return public_key

    @staticmethod
    def compute_shared_secret(private_key: int, peer_public_key: Tuple[int, int]) -> bytes:
        """Compute shared secret using ECDH."""
        shared_point = ECDHKeyExchange.scalar_mult(private_key, peer_public_key)
        if shared_point is None:
            raise ValueError("Invalid shared secret computation")

        # Use the x-coordinate of the shared point
        shared_secret_x = shared_point[0]

        # Hash the shared secret for additional security
        return hashlib.sha256(shared_secret_x.to_bytes(32, 'big')).digest()


def ecdh_key_exchange_example():
    """Demonstrate a complete ECDH key exchange."""
    # Alice generates her key pair
    alice_private_key = ECDHKeyExchange.generate_private_key()
    alice_public_key = ECDHKeyExchange.derive_public_key(alice_private_key)

    # Bob generates his key pair
    bob_private_key = ECDHKeyExchange.generate_private_key()
    bob_public_key = ECDHKeyExchange.derive_public_key(bob_private_key)

    # Key exchange
    alice_shared_secret = ECDHKeyExchange.compute_shared_secret(alice_private_key, bob_public_key)
    bob_shared_secret = ECDHKeyExchange.compute_shared_secret(bob_private_key, alice_public_key)

    # Verify shared secrets match
    assert alice_shared_secret == bob_shared_secret, "Shared secrets do not match!"

    print("ECDH Key Exchange Successful!")
    print("Shared Secret (first 16 bytes):", alice_shared_secret.hex())


if __name__ == "__main__":
    ecdh_key_exchange_example()
