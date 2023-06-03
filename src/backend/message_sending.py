from Crypto.Hash import SHA1
from Crypto.Cipher import DES3


def getKeyId(email):
    return


def getEncryptedPrivateKey(email):
    return


def hashSha1(string):
    h = SHA1.new()
    h.update(bytearray(string, 'utf-8'))
    print(h.hexdigest())
    return


def decryptPrivateKey(hashedPassword, encryptedPrivateKey, algorithm):
    if algorithm == "TripleDES":
        # cipher = DES3.new(hashedPassword, DES3.MODE_CFB)
        # plaintext = b'We are no longer the knights who say ni!'
        # msg = cipher.iv + cipher.encrypt(plaintext)
    elif algorithm == "AES128":
        pass
    return
