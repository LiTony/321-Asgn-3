import hashlib

# diffie-hellman procedure, calculates base^exp % mod
def dh_proc(base, exp, mod):
    ans = 1
    for i in range(exp):
        ans = (ans * base) % mod 
    return ans

Q = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371",16)    
ALPHA = int("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5",16)   

alice_secret = 234
bob_secret = 234

alice_message = dh_proc(ALPHA, alice_secret, Q)
bob_message = dh_proc(ALPHA, bob_secret, Q)

alice_prehash = dh_proc(bob_message, alice_secret, Q)
bob_prehash = dh_proc(alice_message, alice_secret, Q)

alice_key = hashlib.sha256(bytes(alice_prehash))
bob_key = hashlib.sha256(bytes(bob_prehash))

if alice_key.digest() == bob_key.digest():
    print("exchange success!")
else:
    print("exchange failure!")

