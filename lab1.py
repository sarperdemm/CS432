import socket
from Crypto.Hash import SHA256, SHA384, SHA512, HMAC
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP

# ---- Cryptographic Functions ----
# Hash function
def hashWithSHA(message: bytes, algo=SHA256):
    """Hashes a message using the specified algorithm (default: SHA256)."""
    h = algo.new()
    h.update(message)
    return h

# HMAC function
def applyHMACwithSHA(message: bytes, key: bytes, algo=SHA256):
    """Generates an HMAC for the given message using a specified algorithm (default hash: SHA256)."""
    h = HMAC.new(key, digestmod=algo)
    h.update(message)
    return h

# AES encryption & decryption
def encryptWithAES_CFB(plaintext: bytes, key: bytes, iv: bytes):
    """Encrypts a message using AES in CFB mode."""
    cipher = AES.new(key, AES.MODE_CFB, iv)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def decryptWithAES_CFB(ciphertext: bytes, key: bytes, iv: bytes):
    """Decrypts an AES-encrypted message from file."""
    try:
        cipher = AES.new(key, AES.MODE_CFB, iv)
        decrypted = cipher.decrypt(ciphertext)
        return decrypted
    except (ValueError, KeyError):
        print("Incorrect AES decryption")

# RSA encryption & decryption
def encryptWithRSA(message: bytes, public_key):
    """Encrypts a message using RSA."""
    cipher_rsa = PKCS1_OAEP.new(public_key)
    ciphertext = cipher_rsa.encrypt(message)
    return ciphertext

def decryptWithRSA(ciphertext: bytes, private_key):
    """Decrypts an RSA-encrypted message."""
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted = cipher_rsa.decrypt(ciphertext)
    return decrypted

# RSA signing & verification
def signWithRSA(message: bytes, private_key, algo=SHA256):
    """Signs a message using RSA and saves the signature."""
    h = algo.new(message)
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

def verifyWithRSA(message: bytes, public_key, signature, algo=SHA256):
    """Verifies an RSA signature from file."""
    h = algo.new(message)
    result = False
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        result = True
    except (ValueError, TypeError):
        print("Signature verification failed")
    return result


# Client reads the keys
with open("keys/AES128key_IV.bin", 'rb') as file:
    AES128key = file.read(16)
    AES128IV = file.read(16)

with open("keys/plaintext.txt", 'r') as file:
    plaintext = file.readline().strip()

with open("keys/RSA2048key.pem", "rb") as file:
    RSAKey2048_private = RSA.import_key(file.read())
    RSAKey2048_public = RSAKey2048_private.public_key()

def decryptWithAES_CBC(ciphertext: bytes, key: bytes, iv: bytes):
    """Decrypts a message using AES-128 in CBC mode and removes PKCS#7 padding if present."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    # Remove any potential PKCS#7 padding; the server might or might not use it.
    try:
        unpadded = unpad(decrypted, 16)
        return unpadded
    except ValueError:
        # If there's no padding or something is off, you can slice to 4 bytes if you know the server always sends 4 ASCII chars
        return decrypted


# Connect to server
# if doesnt work use 10.3.0.239
IP = "harpoon1.sabanciuniv.edu"
PORT = 9999
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((IP, PORT))

# ---- MAIN  -----

# Your main code goes here
# You can also add more functions if you see necessary



encrypted_token = client_socket.recv(16)
decrypted_token = decryptWithAES_CBC(encrypted_token, AES128key, AES128IV)
token_bytes = decrypted_token[:4]


token_hash_obj = hashWithSHA(token_bytes, algo=SHA256)
token_hash_256 = token_hash_obj.digest()

my_full_name = "İsmail Sarp Erdem"
hmac_obj = applyHMACwithSHA(my_full_name.encode('utf-8'), token_hash_256, algo=SHA512)
hmac_hex = hmac_obj.hexdigest()

message_to_server = f"{my_full_name}:{hmac_hex}"
client_socket.sendall(message_to_server.encode('utf-8'))


encrypted_rsa_data = client_socket.recv(256)
rsa_decrypted = decryptWithRSA(encrypted_rsa_data, RSAKey2048_private)

aes256_key = rsa_decrypted[:32]
aes256_iv  = rsa_decrypted[32:48]

ciphertext_bytes = encryptWithAES_CFB(plaintext.encode('utf-8'), aes256_key, aes256_iv)


signature_bytes = signWithRSA(ciphertext_bytes, RSAKey2048_private, algo=SHA256)
ciphertext_hex = ciphertext_bytes.hex()
signature_hex   = signature_bytes.hex()

final_message_str = f"{ciphertext_hex}:{signature_hex}"
client_socket.sendall(final_message_str.encode('utf-8'))

final_response = client_socket.recv(64)
print("Server response:", final_response.decode('utf-8', errors='ignore'))

client_socket.close()