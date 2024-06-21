"""
Description:
This Python file contains functions that assist in creating
and managing EC (elliptic curve) keys.

"""
import hashlib
import secrets
from tinyec import registry
from utility.constants import BLOCK_SIZE, MODE_PLAYGROUND, MODE_SERVER, MODE_CLIENT


def compress(key):
    """
    Compresses a key generated by ECDH key
    exchange protocol into a hex representation
    of 65 hex digits.

    @param key:
        The key to be compressed

    @return: Compressed Key
        A compressed key represented as a hex string
    """
    return hex(key.x) + hex(key.y % 2)[2:]


def derive_shared_secret(pvt_key: int, pub_key):
    """
    Derives the shared secret between a private key
    and another host's public key by performing ECC point
    multiplication.

    @param pvt_key:
        An owning host's private key

    @param pub_key:
        The other host's public key

    @return: shared_secret
        A 16-byte shared key derived from the 'brainpoolP256r1'
        elliptic curve and then hashed using SHA3-256.
    """
    # EC point multiplication with private and public key
    shared_key = pvt_key * pub_key

    # Use the X-coordinate of the shared key (point on an elliptic curve) and convert to bytes
    shared_key_bytes = shared_key.x.to_bytes((shared_key.x.bit_length() + 7) // 8, 'big')

    # Compress the key by taking only the first 16-bytes of the SHA256 hash
    shared_key_hash = hashlib.sha3_256(shared_key_bytes).digest()
    return shared_key_hash[:BLOCK_SIZE]


def generate_keys(mode: str):
    """
    Generates a public/private key pair using
    the brainpoolP256r1 elliptic curve.

    @param mode:
        A string that declares whether calling class is
        a 'Server' or 'Client'

    @return: private_key, public_key
    """
    # Define BrainPool 256-bit Elliptic Curve
    curve = registry.get_curve('brainpoolP256r1')

    # Generate Private Key (a random int from [1, n-1])
    private_key = secrets.randbelow(curve.field.n)

    # Generate Public Key (a * G)
    public_key = private_key * curve.g
    print("[+] ECDH Private/Public Key pairs have been successfully generated!")

    if mode == MODE_SERVER:
        print(f"[+] Server private key: {hex(private_key)}")
        print(f"[+] Server public key: {compress(public_key)}")

    if mode == MODE_CLIENT:
        print(f"[+] Client private key: {hex(private_key)}")
        print(f"[+] Client public key: {compress(public_key)}")

    if mode == MODE_PLAYGROUND:
        print(f"[+] Private key: {hex(private_key)}")
        print(f"[+] Public key: {compress(public_key)}")

    return private_key, public_key


def generate_shared_secret():
    """
    Generates a random shared secret key using ECDH key exchange
    and the 'brainpoolP256r1' elliptic curve.

    @attention Use Case:
        Only used by CipherPlayground class (for generation of
        main key and avalanche effect analysis SKAC in Cipher
        Playground)

    @return: hash_object[:block_size]
        A hash of the shared secret (according to a block size)
    """
    print("[+] GENERATING SHARED EC KEY: Now generating an elliptic curve shared key...")
    pvt_key_1, pub_key_1 = generate_keys(mode=MODE_PLAYGROUND)
    pvt_key_2, pub_key_2 = generate_keys(mode=MODE_PLAYGROUND)
    shared_secret = derive_shared_secret(pvt_key_1, pub_key_2)
    print(f"[+] OPERATION SUCCESSFUL: The main key for cipher playground is {shared_secret.hex()}")
    return shared_secret
