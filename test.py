import base64
import hashlib
from sys import winver
from Cryptodome.Cipher import AES as domeAES
from Cryptodome.Random import get_random_bytes
from Crypto import Random
from Crypto.Cipher import AES as cryptoAES
import os
import os.path
from os import listdir
from os.path import isfile, join
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from Crypto.Signature import PKCS1_v1_5

clear = lambda: os.system("cls")

#------------------ Encrypt&DeCrypt TEXT  ------------------#
BLOCK_SIZE = cryptoAES.block_size

key = "my_secret_key".encode()
__key__ = hashlib.sha256(key).digest()

def encrypt(raw):
    BS = cryptoAES.block_size
    pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
    raw = base64.b64encode(pad(raw).encode('utf8'))
    iv = get_random_bytes(cryptoAES.block_size)
    cipher = cryptoAES.new(key= __key__, mode= cryptoAES.MODE_CFB,iv= iv)
    a= base64.b64encode(iv + cipher.encrypt(raw))
    IV = Random.new().read(BLOCK_SIZE)
    aes = domeAES.new(__key__, domeAES.MODE_CFB, IV)
    b = base64.b64encode(IV + aes.encrypt(a))
    return b

def decrypt(enc):
    passphrase = __key__
    encrypted = base64.b64decode(enc)
    IV = encrypted[:BLOCK_SIZE]
    aes = domeAES.new(passphrase, domeAES.MODE_CFB, IV)
    enc = aes.decrypt(encrypted[BLOCK_SIZE:])
    unpad = lambda s: s[:-ord(s[-1:])]
    enc = base64.b64decode(enc)
    iv = enc[:cryptoAES.block_size]
    cipher = cryptoAES.new(__key__, cryptoAES.MODE_CFB, iv)
    b=  unpad(base64.b64decode(cipher.decrypt(enc[cryptoAES.block_size:])).decode('utf8'))
    return b

def en_text(data_s):
    #encrypt
    with open(data_s, 'r') as f:
        s = f.read() 
    with open(data_s, 'wb+') as f:
        en_d = encrypt(s)
        f.write(en_d)

    #digitalSig
    key = RSA.import_key(open('pv.key').read())
    h = SHA512.new(en_d)

    sg = PKCS1_v1_5.new(key)
    signa = sg.sign(h)

    with open("hash.txt", "wb") as f:
        f.write(signa)

def de_text(data_s):
    #digital veri
    key = RSA.import_key(open('pb.key').read())
    with open("hash.txt", "rb") as f:
        signa = f.read()
    
    #decrypt
    with open(data_s, 'rb') as f:
        s = f.read()

    with open(data_s,"w+") as f:
        de_d =decrypt(s)
        f.write(de_d)
    
    h = SHA512.new(s)
    PKCS1_v1_5.new(key).verify(h, signa)
    


#-------------------------- Gen Key RSA --------------------------#
key = RSA.generate(2048)
private_key = key.export_key()
with open("pv.key", "wb") as f:
    f.write(private_key)

public_key = key.publickey().export_key()
with open("pb.key", "wb") as f:
    f.write(public_key)

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
        daf_en = str(input("File Encrypt: "))
        clear()
    elif choose == 4:
        def_de = str(input("File Decrypt: "))
        clear()