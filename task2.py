import hashlib
from Crypto.Cipher import AES
# diffie-hellman procedure, calculates base^exp % mod
def dh_proc(base, exp, mod):
    ans = 1
    for i in range(exp):
        ans = (ans * base) % mod 
    return ans

# 128 bits = 16B
def pad_128_bits(message):
    offset = 16 - len(message) % 16
    if offset == 16:
        offset = 0
    offsetArr = [offset for x in range(offset)]
    print("arr: \n", offsetArr)
    offsetBytes = bytearray(offsetArr)
    print("bytes: \n", offsetBytes)
    message = message + offsetBytes
    return message

Q = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371",16)    
ALPHA = int("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5",16)

alice_secret = 1600
bob_secret = 2150

def part1():
    alice_message = dh_proc(ALPHA, alice_secret, Q)
    bob_message = dh_proc(ALPHA, bob_secret, Q)

    #Task 2 (1)
    #Mallory Interception START

    alice_message = Q   #setting the key exchange to be Q effectively means Q to ANY POWER mod Q = 0.
    bob_message = Q

    #Mallory Interception END

    alice_prehash = dh_proc(bob_message, alice_secret, Q)
    bob_prehash = dh_proc(alice_message, bob_secret, Q)
    mallory_prehash = dh_proc(Q, 1, Q)

    alice_prehash_bytes = alice_prehash.to_bytes((alice_prehash.bit_length() + 7) // 8, 'big')
    bob_prehash_bytes = bob_prehash.to_bytes((bob_prehash.bit_length() + 7) // 8, 'big')
    mallory_prehash_bytes = mallory_prehash.to_bytes((mallory_prehash.bit_length() + 7) // 8, 'big')
    print("Alice, Bob, Mallory Prehashes\n")
    print(alice_prehash)
    print(bob_prehash)
    print(mallory_prehash)

    alice_key = hashlib.sha256(bytes(alice_prehash_bytes))
    bob_key = hashlib.sha256(bytes(bob_prehash_bytes))
    mallory_key = hashlib.sha256(bytes(mallory_prehash_bytes))

    print("Alice, Bob Keys\n")
    print(alice_key.digest())
    print(bob_key.digest())
    print("Mallory's Sneaky Key Steal\n")
    print(mallory_key.digest())

    if alice_key.digest() == bob_key.digest():
        print("exchange success!")
    else:
        print("exchange failure!")

    iv = b"0123456789012345"
    aesCipher = AES.new(alice_key.digest(), AES.MODE_CBC, iv) #alice_key = bob_key = mallory_key
    malloryCipher = AES.new(mallory_key.digest(), AES.MODE_CBC, iv)

    aliceChatMessage = pad_128_bits(b"Hi Bob, how are you?")
    bobChatMessage = pad_128_bits(b"Hi Alice, how are you?")
    aCM_ENC = aesCipher.encrypt(aliceChatMessage)
    bCM_ENC = aesCipher.encrypt(bobChatMessage)

    print("Mallory can decrypt this")
    print("Mallory sees alice say: \n")
    print(malloryCipher.decrypt(aCM_ENC))
    print("Mallory sees bob say: \n")
    print(malloryCipher.decrypt(bCM_ENC))
    return

def part2():
    alice_message = dh_proc(ALPHA, alice_secret, Q)
    bob_message = dh_proc(ALPHA, bob_secret, Q)

    #Task 2 (2)
    #Mallory Interception START

    

    #Mallory Interception END

    return

def main():
    part1()
    #part2()

if __name__ == "__main__":
    main()
