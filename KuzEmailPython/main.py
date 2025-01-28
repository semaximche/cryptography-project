import ast

from ecdh_keyex import ECDHKeyExchange
from elgamal_signature import Generator, DigitalSignature
from kuz_encryption import Kuznechik

if __name__ == "__main__":
    sender_private_encryption_key = 0
    sender_public_encryption_key = 0
    recipient_private_encryption_key = 0
    recipient_public_encryption_key = 0
    sender_private_signature_key = 0
    sender_public_signature_key = 0
    recipient_private_signature_key = 0
    recipient_public_signature_key = 0

    # El Gamal Setup
    generator = Generator()
    p = 42863  # choose big number
    g = generator.find_generator(p)
    ds = DigitalSignature(p, g)

    # Read configuration file
    with open("config.txt", 'r') as config_fp:
        lines = config_fp.readlines()
        for line in lines:
            index = line.find('=')
            if line[:index] == "SENDER_ENCRYPTION_PRIVATE_KEY":
                sender_private_encryption_key = ast.literal_eval(line[index+1:])
            elif line[:index] == "SENDER_ENCRYPTION_PUBLIC_KEY":
                sender_public_encryption_key = ast.literal_eval(line[index+1:])
            elif line[:index] == "RECIPIENT_ENCRYPTION_PRIVATE_KEY":
                recipient_private_encryption_key = ast.literal_eval(line[index+1:])
            elif line[:index] == "RECIPIENT_ENCRYPTION_PUBLIC_KEY":
                recipient_public_encryption_key = ast.literal_eval(line[index+1:])
            elif line[:index] == "SENDER_SIGNATURE_PRIVATE_KEY":
                sender_private_signature_key = ast.literal_eval(line[index + 1:])
            elif line[:index] == "SENDER_SIGNATURE_PUBLIC_KEY":
                sender_public_signature_key = ast.literal_eval(line[index + 1:])
            elif line[:index] == "RECIPIENT_SIGNATURE_PRIVATE_KEY":
                recipient_private_signature_key = ast.literal_eval(line[index+1:])
            elif line[:index] == "RECIPIENT_SIGNATURE_PUBLIC_KEY":
                recipient_public_signature_key = ast.literal_eval(line[index+1:])

    # Get shared key
    shared_symmetric_key = int.from_bytes(ECDHKeyExchange.compute_shared_secret(sender_private_encryption_key,
                                                                                recipient_public_encryption_key),
                                          "big")

    # Print menu
    print("1. Encrypt a message and sign")
    print("2. Verify and decrypt a message")
    print("3. Generate new key pairs")
    print("4. Exit")
    choice = input("Enter your choice: ")

    if choice == "1":
        print("--------------------")
        message = input("Enter message to encrypt:")
        print("--------------------")

        # Encrypt
        encrypted_message = Kuznechik.encrypt(message, shared_symmetric_key)

        # Sign
        ds.private_key = sender_private_signature_key
        ds.public_key = sender_public_signature_key
        r, s = ds.sign_message(encrypted_message)
        encrypted_message += f":{r},{s}"
        print(encrypted_message)

    if choice == "2":
        print("--------------------")
        message = input("Enter message to decrypt:")
        print("--------------------")

        # Verify
        r = int(message[message.find(":")+1:message.find(",")])
        s = int(message[message.find(",")+1:])
        message = message[:message.find(":")]
        print(r, s)
        ds.private_key = sender_private_signature_key
        ds.public_key = sender_public_signature_key
        is_valid = ds.verify_signature(message, r, s)
        print(f"Signature Validation: {is_valid}")

        # Decrypt
        decrypted_message = Kuznechik.decrypt(message, shared_symmetric_key)
        print(decrypted_message)

    if choice == "3":
        print("--------------------")
        print("Generating 2 pairs of ECDH keys:")
        for i in range(2):
            private_key = ECDHKeyExchange.generate_private_key()
            public_key = ECDHKeyExchange.derive_public_key(private_key)
            print("Private key:", private_key)
            print("Public key:", public_key)
            print("-")
        print("Generating 2 pairs of El Gamal keys:")
        for i in range(2):
            ds.key_generation()
            print("Private key:", ds.private_key)
            print("Public key:", ds.public_key)
            print("-")

