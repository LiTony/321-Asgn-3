from Crypto.Util.number import getPrime
import sys
E=65537
# diffie-hellman procedure, calculates base^exp % mod
def dh_proc(base, exp, mod):
    ans = 1
    for i in range(exp):
        ans = (ans * base) % mod 
    return ans

# https://en.wikipedia.org/wiki/Exponentiation_by_squaring 
# fast exponentiation by squares
def fastExp(base, exp, mod):
    if exp == 0:
        return 1
    isOdd = exp & 1
    if isOdd:
        half = fastExp(base, (exp-1)//2, mod)
        return (half * half * base) % mod
    else:
        half = fastExp(base, exp//2, mod)
        return (half * half) % mod

# https://en.wikipedia.org/wiki/Euclidean_algorithm#Procedure
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

def tableAlg(a, b):
    r0,r1 = a, b
    s0,s1 = 1, 0
    t0,t1 = 0, 1
    #start of recursion
    ans = tableHelper(0, r0, r1, s0, s1, t0, t1)
    print(ans)
    if (ans[4] < 0):
        return ans[3]
    return ans[3] + ans[4]

def tableHelper(q, rN, rN1, sN, sN1, tN, tN1):
    if(rN1 == 0):
        return q, rN, rN1, sN, sN1, tN, tN1
    else:
        newQ = rN//rN1
        newR = rN1
        newRN1 = rN - newQ * rN1
        newS = sN1
        newSN1 = sN - newQ * sN1
        newT = tN1
        newTN1 = tN - newQ * tN1
        return tableHelper(newQ, newR, newRN1 , newS, newSN1, newT, newTN1)

def findInverse(num, mod):
    for i in range(mod):
        if (i * num) % mod == 1:
            return i
    return None
    
def test():
    print("generating primes...")
    p = getPrime(2048) # 2048 bit primes
    q = p
    while (q == p):
        q = getPrime(2048)
    n = p * q
    euler_totient = (p-1) * (q-1)

    pub_key = (E, n)
    # get multiplicative inverse d
    d = abs(tableAlg(E, euler_totient))
    pri_key = (d, n)

    plaintext = "hello world"
    pt_as_number = int.from_bytes(plaintext.encode('utf-8'), "big")

    ciphertext = fastExp(pt_as_number, E, n) #4096 -> 4096 13^65537 mod n --> ct <= n
    print(d.bit_length())
    pt_decrypt = fastExp(ciphertext, d, n) #(2^4096)^(2^4096) (13^65537)^(2^4096) => 2^4096 operations
    pt_bytes = pt_decrypt.to_bytes(pt_decrypt.bit_length(), 'big')
    print(pt_bytes.decode('utf-8'))

def smallTest():
    print("generating primes...")
    p = getPrime(8) # 2048 bit primes
    q = p
    while (q == p):
        q = getPrime(8)

    n = p * q
    euler_totient = (p-1) * (q-1)
    print(p, q)

    pub_key = (E, n)
    # get multiplicative inverse d
    d = abs(tableAlg(E, euler_totient))
    print(findInverse(E, euler_totient))
    print("d: ", d)
    pri_key = (d, n)

    plaintext = "h"
    # str->bytes->int
    
    pt_as_number = int.from_bytes(plaintext.encode('utf-8'), "big")
    print(pt_as_number)

    ciphertext = fastExp(pt_as_number, E, n) #4096 -> 4096 13^65537 mod n --> ct <= n
    print("ct: ", ciphertext)


    print("ct bitlength: ", ciphertext.bit_length(), "\nd bitlength: ", d.bit_length(), "\nn bitlength: ", n.bit_length())
    
    #Above is Good.

    pt_decrypt = fastExp(ciphertext, d, n) #(2^4096)^(2^4096) (13^65537)^(2^4096) => 2^4096 operations
    print("pt_decrypt: ", pt_decrypt)
    print("dh_proc: ", dh_proc(ciphertext, d, n))
    # int -> bytes
    pt_bytes = pt_decrypt.to_bytes(pt_decrypt.bit_length(), "big")
    print(pt_bytes, pt_decrypt)
    print(pt_bytes.decode('utf-8'))

def expTest():
    p = getPrime(2048) # 2048 bit primes
    q = getPrime(2048)
    print(fastExp(p, q, p*q))

def tableTest():
    p = 239
    q = 151
    euler_totient = (p-1) * (q-1)
    p, q = E, euler_totient

    # pub_key = (E, n)
    print(extEuclidAlg(p, q)[0])
    print(findInverse(p, q))
    # print("d: ", d)
    print(tableAlg(p, q))
    
sys.setrecursionlimit(4100)
while(True):
    test()