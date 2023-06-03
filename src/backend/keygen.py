from Crypto.PublicKey import DSA
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1


def generate(algorithm, keyLength):
    """Returns tuple (privateKey, publicKey)"""
    if algorithm == "rsa":
        return generateRsaKey(keyLength)
    elif algorithm == "dsa":
        return generateDsaKey(keyLength)

    return None, None


def generateRsaKey(keyLength):
    key = RSA.generate(keyLength)
    return key, key.public_key()


def generateDsaKey(keyLength):
    key = DSA.generate(keyLength)
    return key, key.public_key()
