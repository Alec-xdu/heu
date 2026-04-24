Implementation of a Variant of Improved Symmetric Homomorphic Encryption(iSHE)

KeyGen(key_size):

- Sample a $k_p$-bit (usually $k_p=1536$) prime $p$
- Sample a $k_q$-bit (usually $k_q=512$) primes $q$
- Set $k_{r1}, k_{r2}$, the length of random numbers
- Set the message space parameter $k_m=64$ 
- The private key is $(p, q)$ and the public parameter is all the parameters $(k_p, k_q, k_{r1}, k_{r2}, k_m)$ and pre-computed ciphertext of $0$

Encryption(sk, pp, m):

- Sample $r_1 \gets \{0,1\}^{k_{r1}}, r_2 \gets \{0,1\}^{k_{r2}}$
- The ciphertext is $c = r_1 \cdot p + r_2 \cdot q + (m\ \text{mod}\ (2^{k_m-1}-1))$

Decryption(sk, c):

- Compute $m' = c\ (\text{mod}\ p\ (\text{mod}\ q\ (\ \text{mod}\ (2^{k_m-1}-1)))$
- If $m' \le 2^{k_m-1}-1$ return m' else return $m'- 2^{k_m-1}-1$

Additive homomorphisms:

- Add $(c_1, c_2) = c_1 + c_2$
- AddPlain $(c, m) = c + (m\ (\ \text{mod}\ 2^{k_m-1}-1))$
- Negate $\text{MulPlain}(a, 2^{k_m-1}-2)$

Multiplicative homomorphism:

- MulPlain $(c, m) = c \cdot m$

This implement focus on 2048bits key size and 112bit security. The argument keysize in key_generator is actually the scale of dataset.    