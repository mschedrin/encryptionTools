import base64

from Crypto import Random
from Crypto.Cipher import AES

key = "SuperSecret" #Insecure and just for testing
plaintext = "Secret message please don't look"

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)

def padKey(s): #Pad key to 32 bytes for AES256
    return (s * (int(32/len(s))+1))[:32]

class AESCipher:

    def __init__(self, key):
        self.key = key

    def encrypt(self, raw):
        raw = pad(raw)
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw ) )

paddedKey = padKey(key)
cipher = AESCipher(paddedKey)

encrypted = str(cipher.encrypt(plaintext))
encrypted = encrypted[2:-1]

print("Key:", base64.b64encode(paddedKey))
print("Plaintext:",plaintext)
print("Encrypted and B64:",encrypted)