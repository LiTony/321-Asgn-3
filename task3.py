from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
import sys, hashlib
from task2 import pad_128_bits
E=65537

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

# https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
# use extended euclidian algo to find x, y s.t.
# ax + by = gcd(a, b); a > b
# returns mod inverse
def tableAlg(a, b):
    r0,r1 = a, b
    s0,s1 = 1, 0
    t0,t1 = 0, 1
    #start of recursion
    ans = tableHelper(0, r0, r1, s0, s1, t0, t1)
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
    
def part1():
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

    ciphertext = fastExp(pt_as_number, E, n) 
    pt_decrypt = fastExp(ciphertext, d, n)
    pt_bytes = pt_decrypt.to_bytes(pt_decrypt.bit_length(), 'big')
    print(pt_bytes.decode('utf-8'))

def part2():
    print("generating primes...")
    p = getPrime(2048) # 2048 bit primes
    q = p
    while (q == p):
        q = getPrime(2048)
    n, e = p * q, E
    euler_totient = (p-1) * (q-1)
    d = abs(tableAlg(e, euler_totient))
    
    # bob computing message
    bob_s = int.from_bytes("asdf".encode('utf-8'), "big")
    bob_key = hashlib.sha256(bytes(bob_s)).digest()
    c = fastExp(bob_s, e, n)

    # mallory intercept
    c = c^c
    iv = b"0123456789012345"
    mallory_key = hashlib.sha256(bytes(c)).digest()
    malloryCipher = AES.new(mallory_key, AES.MODE_CBC, iv)

    # alice receive
    alice_s = fastExp(c, d, n)
    alice_key = hashlib.sha256(bytes(alice_s)).digest()
    alice_m = b"Hi Bob!"
    print("Alice wants to say: ")
    print(pad_128_bits(alice_m))
    
    aesCipher = AES.new(alice_key, AES.MODE_CBC, iv) #alice_key = bob_key = mallory_key
    pt_pad = pad_128_bits(alice_m)
    ct = aesCipher.encrypt(pt_pad)

    #show Mallory's evil
    print("Mallory can decrypt this: ")
    print(malloryCipher.decrypt(ct))



sys.setrecursionlimit(4100)
part2()