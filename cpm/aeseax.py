from Crypto.Cipher import AES

def encrypt(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, authtag = cipher.encrypt_and_digest(data.encode())
    return cipher.nonce + authtag + ciphertext

def decrypt(data, key):
    cipher = AES.new(key, AES.MODE_EAX, data[:16])
    return cipher.decrypt_and_verify(data[32:], data[16:32])
