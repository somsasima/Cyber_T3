import base64
import hashlib
from sys import winver
from Cryptodome import Cipher
from Cryptodome.Cipher import AES as domeAES
from Cryptodome.Random import get_random_bytes
from Crypto import Random
from Crypto.Cipher import AES as cryptoAES
import os
import os.path
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64decode
import getpass

clear = lambda: os.system("cls")

#-------------------------- Gen Key RSA --------------------------------#
key = RSA.generate(2048)

private_key = key.export_key()
with open("pv.key", "wb") as f:
    f.write(private_key)

public_key = key.publickey().export_key()
with open("pb.key", "wb") as f:
    f.write(public_key)

#------------------ Encrypt & DeCrypt TEXT  -----------------------------#
BS = cryptoAES.block_size

key = get_random_bytes(32)

def __key__(key):
    return hashlib.sha256(key).digest()

def encrypt_text(raw):
    pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
    raw = base64.b64encode(pad(raw).encode('utf8'))
    iv = get_random_bytes(BS)
    cipher = cryptoAES.new(key= __key__, mode= cryptoAES.MODE_CFB,iv= iv)
    a= base64.b64encode(iv + cipher.encrypt(raw))
    IV = Random.new().read(BS)
    aes = domeAES.new(__key__, domeAES.MODE_CFB, IV)
    b = base64.b64encode(IV + aes.encrypt(a))
    return b

def decrypt_text(enc):
    encrypted = base64.b64decode(enc)
    IV = encrypted[:BS]
    aes = domeAES.new(__key__, domeAES.MODE_CFB, IV)
    enc = aes.decrypt(encrypted[BS:])
    unpad = lambda s: s[:-ord(s[-1:])]
    enc = base64.b64decode(enc)
    iv = enc[:BS]
    cipher = cryptoAES.new(__key__, cryptoAES.MODE_CFB, iv)
    b=  unpad(base64.b64decode(cipher.decrypt(enc[BS:])).decode('utf8'))
    return b

def en_text(data_s):
    #encrypt
    with open(data_s, 'r') as f:
        s = f.read() 
    with open(data_s, 'wb+') as f:
        en_d = encrypt_text(s)
        f.write(en_d)

    #digitalSig
    key = RSA.import_key(open('pv.key').read())
    
    mes = s.encode('utf_8')
    h = SHA512.new(mes)

    sg = pkcs1_15.new(key)
    signa = sg.sign(h)

    with open("hash.txt", "wb") as f:
        f.write(signa)

def de_text(data_s):
    #decrypt
    with open(data_s, 'rb') as f:
        s = f.read()
    with open(data_s,"w+") as f:
        de_d = decrypt_text(s)
        f.write(de_d)

    #digital veri
    key = RSA.import_key(open('pb.key').read())
    with open("hash.txt", "rb") as f:
        signa = f.read()
    
    mes = de_d.encode('utf_8')
    h = SHA512.new(mes)

    try:
        pkcs1_15.new(key).verify(h, signa)
        print("That True !! Digital Signa !!")
    except (ValueError, TypeError):
        print("GOD Plaease")

#-------------------------- Encrypt & Decrypt File ------------------------#
class En:
    def __init__(self, key):
        self.key = key

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message, key, key_size=256):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def encrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            plaintext = fo.read()
        enc = self.encrypt(plaintext, self.key)
        with open(file_name + ".enc", 'wb') as fo:
            fo.write(enc)
        os.remove(file_name)

    def decrypt(self, ciphertext, key):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def decrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            ciphertext = fo.read()
        dec = self.decrypt(ciphertext, self.key)
        with open(file_name[:-4], 'wb') as fo:
            fo.write(dec)
        os.remove(file_name)

enc = En(key)

while True:
    print("\nchoose what you want o-o!\n")
    choose = int(input("1. Encrypt Text\t\t2. Decrypt Text\t\t3. Encrypt File\t\t4. Decrypt File\n\nEnter Choice: "))
    clear()
    if choose == 1:
        #input text 
        dt_en = str(input("Text Encrypt: "))
        clear()
        #encrypt text
        en_text(dt_en)
    elif choose == 2:
        dt_de = str(input("Text Decrypt: "))
        clear()
        #decrypt text
        de_text(dt_de)
    elif choose == 3:
        enc.encrypt_file(str(input("File Encrypt: ")))
        clear()
    elif choose == 4:
        enc.decrypt_file(str(input("File Decrypt: ")))
        clear()