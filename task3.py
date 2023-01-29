from Crypto.Util.number import getPrime
E=65537

# diffie-hellman procedure, calculates base^exp % mod
def dh_proc(base, exp, mod):
    ans = 1
    for i in range(exp):
        ans = (ans * base) % mod 
    return ans


# use extended euclidian algo to find x, y s.t.
# ax + by = gcd(a, b); a > b
# returns x, y
def extEuclidAlg(a, b):
    remainder = a % b
    s_prev, s = 0, 1
    t_prev, t = 1, - (a//b)
    while remainder != 0:
        a = b
        b = remainder
        s_temp = s
        t_temp = t
        s = s_prev - s*(a//b)
        t = t_prev - t*(a//b)
        s_prev = s_temp
        t_prev = t_temp
        remainder = a % b
    return (s_prev, t_prev)

    
def test():
    p = getPrime(8) # 2048 bit primes
    q = getPrime(8)
    n = p * q
    euler_totient = (p-1) * (q-1)

    pub_key = (E, n)
    # get multiplicative inverse d
    d = abs(extEuclidAlg(E, euler_totient)[0])
    pri_key = (d, n)

    plaintext = "h"
    pt_as_number = int.from_bytes(plaintext.encode('utf-8'), "big")

    ciphertext = dh_proc(pt_as_number, E, n)
    print("ciphertext:", ciphertext)

    pt_decrypt = dh_proc(ciphertext, d, n)
    pt_bytes = pt_decrypt.to_bytes((pt_as_number.bit_length() + 7) // 8, 'big')
    print(pt_bytes.decode('utf-8'))

while(True):
    test()