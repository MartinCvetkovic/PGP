from Crypto.Random import random
from src.backend.key_util import hashSha1


def getKeyIdPublicRing(publicRing, email):
    return ''


def getPublicKeyPublicRing(publicRing, email):
    return ''


def getKeyIdPrivateRing(privateRing, email):
    return ''


def getEncryptedPrivateKey(privateRing, email):
    return ''


def encryptSymmetric(key, plaintext, algorithm):
    if algorithm == "TripleDES":
        pass
    elif algorithm == "AES128":
        pass
    return ''


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
    hashedPassword = hashSha1(password)

    privateKey = exportPrivateKey(encryptedPrivateKey, hashedPassword)

    hashedMessage = hashSha1(message)
    encryptedHashedMessage = encryptAsymmetric(privateKey, hashedMessage, assymetricAlgorithm)

    signatureMessage = concatanateSignatureAndMessage(privateKeyId, encryptedHashedMessage, message)

    sessionKey = getSessionKey()

    encryptedSignatureAndMessage = encryptSymmetric(sessionKey, signatureMessage, symmetricAlgorithm)

    encryptedSessionKey = encryptAsymmetric(publicKey, sessionKey, symmetricAlgorithm)

    return concatanateSignatureAndMessage(publicKeyId, encryptedSessionKey, encryptedSignatureAndMessage)
