from Crypto.Cipher import DES3, AES
from Crypto.Random import random
from src.backend import key_util


def getKeyIdPublicRing(publicRing, email):
    for row in publicRing:
        if row[4] == email:
            return publicRing[2]
    raise Exception("No key id in public ring")


def getPublicKeyPublicRing(publicRing, email):
    for row in publicRing:
        if row[4] == email:
            return publicRing[6]
    raise Exception("No public key in public ring")


def getAlgPrivateRing(privateRing, email):
    for row in privateRing:
        if row[4] == email:
            return privateRing[0]
    raise Exception("No alg in private ring")


def getKeyIdPrivateRing(privateRing, email):
    for row in privateRing:
        if row[4] == email:
            return privateRing[2]
    raise Exception("No key id in private ring")


def getEncryptedPrivateKey(privateRing, email):
    for row in privateRing:
        if row[4] == email:
            return privateRing[7]
    raise Exception("No private key in private ring")


def encryptSymmetric(key, plaintext, algorithm):
    if algorithm == "TripleDES":
        cipher = DES3.new(key, DES3.MODE_CFB)
        return cipher.iv + cipher.encrypt(plaintext)
    elif algorithm == "AES128":
        key = b'Sixteen byte key'
        cipher = AES.new(key, AES.MODE_EAX)
        return cipher.encrypt_and_digest(plaintext)[0]
    return ''


#print(encryptSymmetric(bytearray("1234567890123456", 'utf-8'), "asdfgh", "AES128"))


def encryptAsymmetric(key, plaintext, algorithm):
    if algorithm == "RSA":
        pass
    elif algorithm == "DSA / ElG":
        pass
    return ''


def concatanateSignatureAndMessage(keyId, signature, message):
    return keyId + signature + message


def getSessionKey():
    return random.randint()


def exportPrivateKey(encryptedPrivateKey, hashedPassword):
    return ''


def generateMessage(privateKeyRing, publicKeyRing, email, password, message, assymetricAlgorithm, symmetricAlgorithm):
    privateKeyId = getKeyIdPrivateRing(privateKeyRing, email)
    publicKeyId = getKeyIdPublicRing(publicKeyRing, email)
    encryptedPrivateKey = getEncryptedPrivateKey(privateKeyRing, email)
    publicKey = getPublicKeyPublicRing(publicKeyRing, email)
    hashedPassword = key_util.hashSha1(password)

    privateKey = key_util.decryptPrivateKey(encryptedPrivateKey, hashedPassword, getAlgPrivateRing(privateKeyRing, email))

    hashedMessage = key_util.hashSha1(message)
    encryptedHashedMessage = encryptAsymmetric(privateKey, hashedMessage, assymetricAlgorithm)

    signatureMessage = concatanateSignatureAndMessage(privateKeyId, encryptedHashedMessage, message)

    sessionKey = getSessionKey()

    encryptedSignatureAndMessage = encryptSymmetric(sessionKey, signatureMessage, symmetricAlgorithm)

    encryptedSessionKey = encryptAsymmetric(publicKey, sessionKey, symmetricAlgorithm)

    return concatanateSignatureAndMessage(publicKeyId, encryptedSessionKey, encryptedSignatureAndMessage)
