import hashlib
import secrets

from utility.cipher_utils import (pad_block, encrypt_block, decrypt_block,
                                  unpad_block, get_subkeys_from_user, get_default_subkeys,
                                  is_sub_keys_generated)
from utility.constants import (CIPHER_INIT_MSG, ROUNDS, BLOCK_SIZE, DEFAULT_ROUND_KEYS,
                               OP_ENCRYPT, OP_DECRYPT, INIT_SUCCESS_MSG, FORMAT_FILE,
                               FORMAT_PICTURE, FORMAT_AVALANCHE, ECB, CBC)


class CustomCipher:
    """ A class representing the custom Feistel cipher.

    Attributes:
        mode - The encryption mode of the cipher (default=ECB)
        rounds - The number of rounds the cipher should run (default=8)
        block_size - The block size in bytes (default=8)
        key - The main key used for encryption/decryption
        iv - A randomly generated 8-byte initialization vector for CBC mode (default=None)
        sub_keys - A list containing sub-keys
    """

    def __init__(self, key, mode=ECB, iv=None):
        """
        A constructor for a CustomCipher class object.
        """
        print('=' * 160)
        print(CIPHER_INIT_MSG)
        self.mode = mode
        self.rounds = ROUNDS
        self.block_size = BLOCK_SIZE
        self.key = key
        self.iv = iv
        self.sub_keys = []
        self.__generate_subkeys()
        print(INIT_SUCCESS_MSG)
        print('=' * 160)

    def round_function(self, right_block: bytes, key: bytes):
        """
        A basic round function that involves substitution
        and permutation of the right block, followed by an
        XOR operation with the key.

        @param right_block:
            A string containing the right block

        @param key:
            A string representing the subkey

        @return: result
            A string representing the transformed right block
        """
        # TODO: Incorporate round number to this function
        def substitute(byte: int):
            """
            Substitution of a character(byte) of the right block
            by taking ASCII value modulo 256.

            @param byte:
                A string containing a single character (8-bits)

            @return: chr(ord(byte) % 256)
                The substituted character
            """
            return byte % 256

        def permutation(block: bytes):
            """
            Permutates the right block by reversing the order.

            @param block:
                A string containing characters (bytes) of
                the right block

            @return: block[::-1]
                The reversed order of the right block
            """
            return block[::-1]

        # SUBSTITUTION: Each byte of right block
        new_right_block = bytes(substitute(byte) for byte in right_block)

        # PERMUTATION: Reverses the order of bytes
        new_right_block = permutation(new_right_block)

        # Add the right block + key and take the SHA3-256 hash of the result
        result = new_right_block + key

        # Take the SHA3-256 hash of the result as final product
        hashed_result = hashlib.sha3_256(result).digest()

        # Take the 23rd and 31st byte of the hash result as the output
        return hashed_result[23:31]

    def encrypt(self, plaintext: str | bytes, format=None,
                playground=False, partition=False, verbose=False):
        """
        Encrypts plaintext to ciphertext using a 16-round
        Feistel architecture.

        @attention: Avalanche Analysis
            Only performable when verbose mode is on and
            is executed only in ECB mode

        @param plaintext:
            The plaintext to be encrypted (string)

        @param format:
            A string representing the format to be encrypted
            (FORMAT_USER_INPUT, FORMAT_TEXT_FILE, FORMAT_PICTURE or
            FORMAT_AVALANCHE)

        @param playground:
            A boolean that determines whether playground mode is on
            (default=False)

        @param partition:
            A boolean that determines whether to partition the resulting
            ciphertext into blocks instead of returning it as a whole
            (default=False)

        @param verbose:
            An optional boolean flag to turn on verbose mode;
            used for avalanche analysis (default=False)

        @return: ciphertext or round_data
            The encrypted plaintext (bytes[]); or if verbose
            mode is on return intermediate round_data (list[])
        """
        # Initialize Variables
        ciphertext = b''
        blocks = []

        if is_sub_keys_generated(self.sub_keys, operation=OP_ENCRYPT) is False:
            return None

        # Encode plaintext to bytes (if the format is a string)
        if format not in {FORMAT_FILE, FORMAT_PICTURE, FORMAT_AVALANCHE}:
            plaintext = plaintext.encode()

        if self.mode == ECB:
            if not verbose:  # Don't print if verbose (during avalanche analysis)
                print("[+] ECB ENCRYPTION: Now encrypting plaintext in ECB mode...")

            # Partition the plaintext into blocks and encrypt each block
            for i in range(0, len(plaintext), self.block_size):
                block = plaintext[i:i + self.block_size]

                if len(block) < self.block_size:  # Pad block to 64 bits
                    block = pad_block(self.block_size, block)

                if verbose:  # For avalanche analysis (1 block only)
                    round_data = encrypt_block(self, block, verbose=True)
                    round_data.append(self.key)
                    return round_data

                if partition:
                    blocks.append(encrypt_block(self, block))
                else:
                    ciphertext += encrypt_block(self, block)

        if self.mode == CBC:
            print("[+] CBC ENCRYPTION: Now encrypting plaintext in CBC mode...")

            # If in playground mode, generate IV
            if playground:
                self.iv = secrets.token_bytes(self.block_size)

            previous_block = self.iv

            for i in range(0, len(plaintext), self.block_size):
                block = plaintext[i:i + self.block_size]

                if len(block) < self.block_size:
                    block = pad_block(self.block_size, block)

                block = bytes([a ^ b for a, b in zip(previous_block, block)])  # XOR with previous block
                encrypted_block = encrypt_block(self, block)

                if partition:
                    blocks.append(encrypted_block)
                else:
                    ciphertext += encrypted_block

                previous_block = encrypted_block

        return ciphertext if not partition else blocks

    def decrypt(self, ciphertext: bytes, playground=False, format=None):
        """
        Decrypts ciphertext back into plaintext (or bytes)
        using a 16-round Feistel architecture.

        @param ciphertext:
            The ciphertext to be decrypted (bytes)

        @param playground:
            A boolean determining whether playground mode is on

        @param format:
            A string representing the format to be encrypted
            (FORMAT_USER_INPUT, FORMAT_TEXT_FILE, or FORMAT_PICTURE)

        @return: plaintext
            The decrypted plaintext (string)
        """
        # Initialize Variables
        plaintext_bytes = b''

        if is_sub_keys_generated(self.sub_keys, operation=OP_DECRYPT) is False:
            return None

        if self.mode == ECB:
            print("[+] ECB DECRYPTION: Now decrypting plaintext in ECB mode...")

            # Partition the ciphertext into blocks and decrypt each block
            for i in range(0, len(ciphertext), self.block_size):
                block = ciphertext[i:i + self.block_size]
                decrypted_block = decrypt_block(self, block)
                plaintext_bytes += decrypted_block

        if self.mode == CBC:
            print("[+] CBC DECRYPTION: Now decrypting ciphertext in CBC mode...")

            # Get IV from class attribute
            previous_block = self.iv

            for i in range(0, len(ciphertext), self.block_size):
                block = ciphertext[i:i + self.block_size]
                decrypted_block = decrypt_block(self, block)
                decrypted_block = bytes([a ^ b for a, b in zip(previous_block, decrypted_block)])
                plaintext_bytes += decrypted_block
                previous_block = block

            # If in playground mode, reset IV for next encryption
            if playground:
                self.iv = None

        if len(plaintext_bytes) % self.block_size == 0:
            if format in {FORMAT_FILE, FORMAT_PICTURE}:
                return unpad_block(plaintext_bytes)  # => Return bytes
            else:
                return unpad_block(plaintext_bytes).decode()  # => Return string

    def __generate_subkeys(self):
        """
        Generates a set of sub-keys from the main key on a
        per-round basis based on a permutation scheme.

        @attention: Permutation Scheme
            - a) Perform byte rotation with round number and length of the key
            - b) XOR each byte of the shifted result with the round number

        @return: None
        """
        print("[+] SUBKEY GENERATION: Now processing sub-keys...")
        print(f"[+] Generating sub-keys from the following main key: {self.key.hex()}")

        # Ensure the main key is of sufficient size
        if len(self.key) < self.block_size:
            self.key = (self.key * (self.block_size // len(self.key) + 1))[:self.block_size]

        # Round-key generation with a permutation scheme
        key_bytes = list(self.key)
        for i in range(self.rounds):
            # a) Byte rotation with round number and length of the key
            subkey = key_bytes[i % len(self.key):] + key_bytes[:i % len(self.key)]

            # b) XOR each byte of the shifted result with the round number
            subkey = bytes([byte ^ (i + 1) for byte in subkey])
            self.sub_keys.append(subkey)
            print(f"[+] Round {i + 1}: {subkey.hex()}")

    def process_subkey_generation(self, menu_option=None):
        """
        Generates sub-keys from a main key if the subkey_flag
        is set to True; otherwise, prompts the user to use default
        sub-keys or provide their own sub-keys.

        @attention Main Key (Type Requirement)
            The main key must be in bytes[]

        @attention Use Case
            Used by the UserViewModel when user
            'regenerate sub-keys'.

        @param menu_option:
            An optional parameter used when function
            is called by UserMenu class (default=None)

        @return: None
        """
        # a) Generate subkey if called by UserViewModel (user menu)
        if menu_option is not None:
            self.sub_keys.clear()  # Clear existing sub-keys
            if menu_option == 1:
                self.__generate_subkeys()
            if menu_option == 2:
                self.sub_keys = get_default_subkeys(DEFAULT_ROUND_KEYS)
            if menu_option == 3:
                self.sub_keys = get_subkeys_from_user(self.block_size, self.rounds)

        print(f"[+] OPERATION SUCCESSFUL: {self.rounds} new sub-keys have been added!")
