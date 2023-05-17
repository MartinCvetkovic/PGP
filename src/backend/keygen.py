import rsa
from Crypto.PublicKey import DSA


def generate(algorithm, keyLength):
    if algorithm == "rsa":
        return generateRsaKey(keyLength)
    elif algorithm == "dsa":
        return generateDsaKey(keyLength)

    return None, None


def generateRsaKey(keyLength):
    return rsa.newkeys(keyLength)


def generateDsaKey(keyLength):
    keyPair = DSA.generate(keyLength)
    return keyPair.y, keyPair.x


pubKey, privKey = generate("dsa", 2048)
print(pubKey)
print(privKey)
