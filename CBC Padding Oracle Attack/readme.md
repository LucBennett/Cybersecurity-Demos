# CBC Padding Oracle: Step-by-Step Explanation

## Requirements for a Padding Oracle Attack

For the attack to work, we need:

1. **An Oracle** : a black-box function that:
   - Accepts an IV and a ciphertext.
   - Decrypts them.
   - Tells us **whether the padding at the end of the plaintext is valid** (success/failure).

   Importantly, the oracle **does not** tell us the plaintext, just whether the decrypted data has correct padding.

2. **Original-IV and Original Ciphertext (CT)**: We know at least one ciphertext block and its IV.

3. **PKCS#7 padding scheme:** the plaintext uses PKCS#7 padding (each padding byte equals the number of padding bytes).

## Background: How CBC Decryption Works

**Definitions:**

- $K$: the symmetric encryption key.
- $E_K(\cdot)$: block-cipher **encryption** function under key $K$.
- $D_K(\cdot)$: block-cipher **decryption** function under key $K$ (so $D_K(E_K(x)) = x$).
- $\oplus$: bitwise exclusive OR (XOR)
- $IV$: the initialization vector (one block-sized value used for the first block).
- $P_i$: the $i$-th plaintext block (block-sized).
- $C_i$: the $i$-th ciphertext block (block-sized).
- For convenience define $C_0 := IV$. (This lets the formulas below treat the first block uniformly.)

### Encryption (CBC mode)

To encrypt each plaintext block $P_i$ in CBC mode you first XOR it with the previous ciphertext block $C_{i-1}$ (or with $IV$ for the first block), then encrypt that result:

$$
C_i = E_K\bigl(P_i \oplus C_{i-1}\bigr), \qquad\text{for } i \ge 1.
$$

Using $C_0 := IV$ makes the $i=1$ case the same formula; explicitly:

$$
C_1 = E_K\bigl(P_1 \oplus IV\bigr).
$$

### Decryption (CBC mode)

To recover a plaintext block $P_i$ from a ciphertext block $C_i$, first apply the block-cipher decryption $D_K$ to $C_i$. That produces an intermediate block (often called the _pre-XOR_ or _intermediate value_). Then XOR that intermediate value with the previous ciphertext block $C_{i-1}$ (or with (IV) for the first block):

$$
P_i = D_K(C_i) \oplus C_{i-1}, \qquad\text{for } i \ge 1.
$$

With $C_0 := IV$ this also covers the first block:

$$
P_1 = D_K(C_1) \oplus IV.
$$

Here $D_K(C_i)$ is the raw block output by the block-cipher decryption step (the value **before** the XOR with $C_{i-1})$. Recovering that intermediate value is the core target of a CBC padding-oracle attack, because once you know $D_K(C_i)$ you can compute the plaintext!

### Refresher: What XOR Does

XOR operates bit by bit. For two bits $a$ and $b$:

| a   | b   | a XOR b |
| --- | --- | ------- |
| 0   | 0   | 0       |
| 0   | 1   | 1       |
| 1   | 0   | 1       |
| 1   | 1   | 0       |

XOR is often described like “addition without carrying”, if the bits are different, the result is 1; if they’re the same, the result is 0.

Important properties of XOR:

1. $a \oplus a = 0$
2. $a \oplus 0 = a$
3. $a \oplus b \oplus b = a$ (you can “undo” an XOR by XORing again with the same value)

These properties are what make this attack possible.

## The Goal

Our goal is to recover the **plaintext** $P$ corresponding to a given ciphertext block $C$.

Since CBC decryption is:

$$
P = D_K(C) \oplus IV
$$

If we can find $D_K(C)$, the _intermediate value before the XOR with IV_, then we can compute:

$$
P = D_K(C) \oplus \text{Original-IV}
$$

The padding oracle allows us to indirectly figure out each byte of $D_K(C)$, as I will now show.

## The Core Idea

We will exploit how **PKCS#7 padding** works.

If the plaintext ends with valid padding bytes, each padding byte has the same value as the number of padding bytes.
For example, if the last three bytes are padding, they will look like this:

```
... XX XX 03 03 03
```

If there’s only one byte of padding, it’s:

```
... XX XX XX XX 01
```

The oracle’s job is to check this rule.
We’ll modify bytes in the IV (or previous ciphertext block) and observe whether the padding rule still holds.
If it does, we’ve learned something about $D_K(C)$.

## Step-by-Step Attack

We’ll explain using one ciphertext block $C$ and its associated IV.

### Step 1: Focus on the Last Byte

We begin by trying to discover the **last byte of $D_K(C)$**.

We will modify the last byte of the IV, call it $IV[-1]$.
We try every possible value from $0x00$ to $0xFF$.

For each guess $g$, we create a modified IV:

$$
IV' = IV[0:-1] || g
$$

_$||$ here means concatenate/append. "a" || "b" = "ab"_

We send $(IV', C)$ to the oracle and observe the response. The goal is to find an $IV$ that causes $(D_K(C)[-1]) \oplus IV'[-1] = 0x01$.

- If the oracle reports **invalid padding**, we learn nothing and continue.
- If the oracle reports **valid padding**, we know that **the last byte of the decrypted block**, after XOR with our modified IV either:

1. equals $0x01$ (a valid 1-byte padding).

   $$
   (D_K(C)[-1]) \oplus IV'[-1] = 0x01
   $$

2. equals the CT's real padding.

   $$
   (D_K(C)[-1]) \oplus IV'[-1] = P[-1]
   $$

### Step 2: Determine Which Case It Is

Sometimes, the oracle may return “success” even if our guess coincidentally created a _valid_ padding byte pattern that matches the real plaintext.
We need to rule that out.

To test this:

- Change the **second-to-last byte** $IV[-2]$ to some other random value.
- Keep our successful $IV[-1]$ unchanged.
- Query the oracle again.

If the oracle **still says success**, the padding is _truly $0x01$_, meaning our assumption was correct.

If it **fails now**, the success was accidental, try a different guess for $IV[-1]$.

### Step 3: Recover the Intermediate Value for the Last Byte

Once we have a valid padding case, we can compute the intermediate value:

$$
D_K(C)[-1] = IV'[-1] \oplus 0x01
$$

Remember, this works because we know that:

$$
D_K(C)[-1] \oplus IV'[-1] = 0x01
$$

and XORing both sides by $0x01$ gives:

$$
D_K(C)[-1] = IV'[-1] \oplus 0x01
$$

Now we’ve recovered one byte of $D_K(C)$.

### Step 4: Move to the Second-to-Last Byte

Next, we want to make the padding two bytes long: `0x02 0x02`.

To do that:

- We already know the correct value of the last byte.
- We now modify the last byte in IV so that after decryption it becomes `0x02` instead of `0x01`.

That means we set:

$$
IV'[-1] = IV[-1] \oplus 0x01 \oplus 0x02
$$

This adjustment ensures the last decrypted byte (the padding) now equals `0x02`.

Now we start brute-forcing the second-to-last byte $IV[-2]$:

- For each guess $g \in [0x00, 0xFF]$, set $IV'[-2] = g$
- Keep the last byte as set above.
- Submit $(IV', C)$ to the oracle.

When the oracle says “success,” we know:

$$
D_K(C)[-2] \oplus IV'[-2] = 0x02
$$

So:

$$
D_K(C)[-2] = IV'[-2] \oplus 0x02
$$

_Note: If padding is valid it is not possible for those last two bytes to be anything other than `0x02 0x02` so we don't have to run any additional tests._

### Step 5: Continue for All Bytes

Repeat this logic for each byte moving leftward.

For byte $n$ from the end:

1. Ensure the last $k-1$ bytes of IV are set so that they produce padding $0xk$.
2. Brute-force all 256 possible values of $IV[-k]$.
3. When the oracle reports valid padding, compute:

$$
D_K(C)[-k] = IV'[-k] \oplus 0xk
$$

4. Adjust the last $k$ bytes so that they all decrypt to $0x(k+1)$ for the next round.

### Step 6: Recover the Plaintext

After doing this for all 16 bytes (for AES), we know every byte of $D_K(C)$.

Since CBC decryption is:

$$
P = D_K(C) \oplus IV
$$

We simply XOR our recovered $D_K(C)$ with the **original IV** (not our modified one!) to obtain the plaintext:

$$
P = D_K(C) \oplus \text{Original-IV}
$$

## Applying this to multi-block

This process can be applied to the first block first. For every next ciphertext block, we would use the previous **ciphertext** (not plaintext) block to the left instead of the IV.

Alternatively, this process can be applied to the last block first. For every next ciphertext block going left, we would use the next ciphertext block to the left instead of the IV.

_Note: For a multi-block $CT$ only the last block will have padding so one only need to worry about the trap in step 1 for the last block._
