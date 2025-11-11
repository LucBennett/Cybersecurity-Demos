"""
This script demonstrates a CBC Padding Oracle Attack, as described in the
accompanying document "CBC Padding Oracle Attack.md".

It uses a DemoOracle class that simulates a black-box encryption/decryption
oracle. The oracle reveals whether a given ciphertext/IV pair decrypts to
valid PKCS#7 padding. This information alone is enough to recover the
plaintext without knowing the encryption key.

Algorithm overview:
1. For each byte position (starting from the end of the block), modify the IV
   to force the decrypted padding to appear valid.
2. Use the oracle's yes/no responses to deduce the corresponding intermediate
   value D_K(C) for that byte.
3. Once all bytes of D_K(C) are known, XOR it with the original IV to recover
   the plaintext block.
"""

from DemoOracle import Oracle, BLOCKSIZE


def xor(a, b) -> bytes:
    """Return the byte-wise XOR of two equal-length byte sequences."""
    assert len(a) == len(b), "Inputs must be the same length"
    return bytes(x ^ y for x, y in zip(a, b))


def attack_single_block(iv, block, oracle):
    # The attacker starts with a fake IV (all zeros)
    # This is what they will modify to probe the oracle
    iv_list = list(bytes.fromhex("00" * BLOCKSIZE))

    # Begin attack: discover each byte of D_K(C)
    for i in reversed(range(BLOCKSIZE)):  # process bytes from last to first
        print("BYTE", i)

        # Try every possible guess for this byte (0–255)
        for g in range(0x100):
            # Construct a candidate IV:
            #   - Bytes before i are left unchanged
            #   - Byte i is our guess 'g'
            #   - Bytes after i are adjusted so that they decrypt to PKCS#7 padding
            iv1 = (
                bytes(iv_list[:i])
                + g.to_bytes(1, "big")
                + xor(iv_list[(i + 1) :], [BLOCKSIZE - i] * (BLOCKSIZE - (i + 1)))
            )

            # Align 'vv' pointer over the ith byte
            print(f"    {' ' * (i * 2)}vv")
            print(f"IV' {iv1.hex()}")

            # Ask the oracle whether the padding is valid
            dk, r = oracle.decrypt_check(block, iv1)
            print(f"DK  {dk.hex()}")

            if r:
                # The oracle says the padding is valid — now confirm if it’s a true match
                if i == BLOCKSIZE - 1:
                    # Last byte: could be accidental; verify by changing the previous byte
                    print("THINK I FOUND IT", g)
                    iv2 = (
                        iv1[: (i - 1)]
                        + ((iv1[(i - 1)] + 1) % 0x100).to_bytes(1, "big")
                        + iv1[((i - 1) + 1) :]
                    )
                    print(f"    {' ' * (i * 2)}vv")
                    print(f"IV' {iv2.hex()}")
                    dk2, r2 = oracle.decrypt_check(block, iv2)
                    print(f"DK  {dk2.hex()}")
                    if r2:
                        # Confirmed correct padding — we’ve found D_K(C)[i]
                        print("\t", "CONFIRMED", g)
                        iv_list[i] = g ^ (BLOCKSIZE - i)
                        break
                    else:
                        # False positive, keep guessing
                        print("\t", "FAIL", g)
                        continue
                else:
                    # For all other bytes, a valid padding result means success
                    print("FOUND IT", g)
                    iv_list[i] = g ^ (BLOCKSIZE - i)
                    break
        else:
            # If no valid padding found, attack failed
            print("failed to find correct padding")
            exit(1)

    # Once all intermediate bytes are recovered, XOR with the true IV to get plaintext
    plain = xor(iv_list, iv)
    print("Plain", plain)
    return plain


if __name__ == "__main__":
    # Create an instance of the oracle, which provides:
    #  - encrypt(plaintext): returns (iv, ciphertext)
    #  - decrypt_check(ciphertext, iv): returns (decrypted_block, padding_is_valid)
    oracle = Oracle()

    # Encrypt a known plaintext to get its IV and ciphertext
    plaintext = "Long Secret Message"
    iv, ct = oracle.encrypt(plaintext)

    blocks = [ct[i : i + BLOCKSIZE] for i in range(0, len(ct), BLOCKSIZE)]
    plain = b""
    prev_block = iv
    for block_num, block in enumerate(blocks):
        print("Block", block_num)
        plain_block = attack_single_block(prev_block, block, oracle)
        plain += plain_block
        prev_block = block
    print(plain)
