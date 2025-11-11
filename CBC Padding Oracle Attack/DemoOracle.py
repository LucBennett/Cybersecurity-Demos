"""
Simple demo "padding oracle" implementation used for educational purposes and
for reproducing a CBC padding-oracle attack.

This file exposes:
- BLOCKSIZE: the block size used by the cipher (16 bytes for AES).
- Oracle: a class providing a minimal "oracle" with two operations:
    * encrypt(message: str) -> (iv: bytes, ct: bytes)
        - Encrypts the message under a random secret key using AES-CBC with
          PKCS#7 padding and returns (iv, ciphertext).
    * decrypt_check(ct: bytes, iv: bytes) -> (d_k: bytes, valid_padding: bool)
        - Decrypts ct using the oracle's secret key and provided IV. Returns the
          raw block output of the block-cipher decryption (often called the
          "intermediate value" D_K(C)) and a boolean indicating whether the
          padding was valid. This mimics a vulnerable server that leaks only
          padding-validity information.

Notes / Security:
- This module is intentionally vulnerable (it provides an oracle that reveals
  padding validity). Use it only for education, testing, and demonstrations.
- In a real system, the oracle would not return intermediate values; it would
  likely only reveal timing/response differences. The `decrypt_check` function
  returns D_K(C) to make it easier to trace and debug padding oracle attacks.
- For real cryptographic use, never expose padding check results directly to
  untrusted callers and always use authenticated encryption (e.g., AES-GCM)
  or apply an encrypt-then-MAC scheme.

Implementation detail:
- Each call to `encrypt` creates a fresh AES cipher object so each encryption
  uses a fresh random IV. The random key is generated once when the Oracle is
  instantiated.
"""

import os
from typing import Tuple

# pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# AES block size in bytes (16 bytes for AES)
BLOCKSIZE: int = 16


class Oracle:
    """
    A minimal padding oracle for demonstration.

    Attributes
    ----------
    key : bytes
        The secret random AES key (BLOCKSIZE bytes).
    """

    def __init__(self) -> None:
        """
        Create an Oracle with a random secret key.

        The key is persistent for the lifetime of the Oracle instance so that
        encrypt/decrypt operations use the same key (as in a typical server).
        """
        self.key: bytes = os.urandom(BLOCKSIZE)

    def encrypt(self, message: str) -> Tuple[bytes, bytes]:
        """
        Encrypt a UTF-8 string under AES-CBC with PKCS#7 padding.

        A fresh AES cipher object is created for each encryption so that a new
        random IV is used every time (this mirrors how servers normally
        generate IVs).

        Parameters
        ----------
        message : str
            Plaintext message to encrypt.

        Returns
        -------
        (iv, ct) : Tuple[bytes, bytes]
            iv: the random initialization vector (BLOCKSIZE bytes)
            ct: the ciphertext produced by AES-CBC over the padded message
        """
        # Create a new AES-CBC cipher — this generates a fresh random IV
        cipher = AES.new(self.key, AES.MODE_CBC)
        iv = cipher.iv
        # Pad the input using PKCS#7 to a multiple of BLOCKSIZE and encrypt
        ct = cipher.encrypt(pad(message.encode("utf-8"), block_size=BLOCKSIZE))
        return iv, ct

    def decrypt_check(self, ct: bytes, iv: bytes) -> Tuple[bytes, bool]:
        """
        Decrypt the ciphertext with the provided IV and check PKCS#7 padding.

        This function returns two things:
          - d_k (bytes): the raw output of the block-cipher decryption step
            (i.e., D_K(C)). This is the intermediate value *before* the XOR
            with the previous ciphertext/IV. Returning this value is useful
            for debugging and demonstrations.
          - valid (bool): True if the padding is valid, False otherwise.

        Note: In a real oracle vulnerability, the attacker typically does NOT
        receive `d_k`; they only learn whether padding is valid. We return
        `d_k` here purely to make experiments and logging easier.

        Parameters
        ----------
        ct : bytes
            Ciphertext to decrypt (multiple of BLOCKSIZE).
        iv : bytes
            Initialization vector to use for decryption (BLOCKSIZE bytes).

        Returns
        -------
        (d_k, valid) : Tuple[bytes, bool]
            d_k: the decrypted bytes before unpadding (i.e., the raw plaintext
                 block(s) after block-cipher decryption but before XOR.)
            valid: True if unpadding succeeded (valid PKCS#7); False otherwise.

        Behavior
        --------
        - If unpadding succeeds, returns (d_k, True).
        - If unpadding fails (ValueError from unpad), returns (d_k, False).
        - If the user passes an IV of incorrect length or ciphertext of an
          incorrect length, AES.new or decrypt may raise — those exceptions are
          not swallowed here (to keep the demo simple and explicit).
        """
        # Create a new AES-CBC cipher using the stored secret key and provided IV
        cipher2 = AES.new(self.key, AES.MODE_CBC, iv=iv)

        # Decrypt the ciphertext. This returns the raw bytes which still
        # contain PKCS#7 padding at the end. We keep this raw value (d_k)
        # because attackers/learners often target this intermediate value.
        d_k = cipher2.decrypt(ct)

        # Try to unpad to determine whether padding is valid. unpad will
        # raise ValueError if padding is invalid.
        try:
            # If unpad succeeds we ignore the returned value (the unpadded
            # plaintext), but its success tells us the padding was valid.
            _ = unpad(d_k, block_size=BLOCKSIZE)
            return d_k, True
        except ValueError:
            # Invalid padding: return the raw decrypted bytes and False.
            return d_k, False


# Simple example usage when this module is run directly.
if __name__ == "__main__":
    oracle = Oracle()
    iv, ct = oracle.encrypt("Secret")
    print("IV:", iv.hex())
    print("CT:", ct.hex())

    d_k, valid = oracle.decrypt_check(ct, iv)
    print("Decrypted (raw) D_K(C):", d_k.hex())
    print("Padding valid?", valid)
