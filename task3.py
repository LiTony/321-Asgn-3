from Crypto.Util.number import getPrime
E=65537

# diffie-hellman procedure, calculates base^exp % mod
def dh_proc(base, exp, mod):
    ans = 1
    for i in range(exp):
        ans = (ans * base) % mod 
    return ans

# finds mod multiplicative inverse of num mod mod
def findInverse(num, mod):
    for i in range(mod):
        if (i * num) % mod == 1:
            return i
    return None
    
def test():
    p = getPrime(2048) # 2048 bit primes
    q = getPrime(2048)
    n = p * q
    euler_totient = (p-1) * (q-1)

    pub_key = (E, n)
    d = findInverse(E, euler_totient)
    pri_key = (d, n)

    plaintext = "hello world"
    pt_as_number = int.from_bytes(plaintext.encode('utf-8'), "big")

    ciphertext = dh_proc(plaintext, E, n)
    print("ciphertext:", ciphertext)

    pt_decrypt = dh_proc(ciphertext, d, n)
    pt_bytes = pt_decrypt.to_bytes((pt_as_number.bit_length() + 7) // 8, 'big')
    print(pt_bytes.decode('utf-8'))

test()