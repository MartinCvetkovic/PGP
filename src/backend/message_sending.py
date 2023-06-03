from Crypto.Cipher import DES3, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
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
        # return cipher.iv + cipher.encrypt(bytearray(plaintext, "utf-8")) # mozda ova varijanta radi, ako trenutna nece
        return cipher.encrypt(bytearray(plaintext, "utf-8"))
    elif algorithm == "AES128":
        cipher = AES.new(key, AES.MODE_EAX)
        return cipher.encrypt_and_digest(bytearray(plaintext, "utf-8"))[0]
    return ''


def encryptAsymmetricAuthentication(key, plaintext, algorithm):
    if algorithm == "RSA":
        cipher_rsa = PKCS1_OAEP.new(key)
        return cipher_rsa.encrypt(get_random_bytes(16))
    elif algorithm == "DSA / ElG":
        pass
    return ''


def encryptAsymmetricSecrecy(key, plaintext, algorithm):
    if algorithm == "RSA":
        cipher_rsa = PKCS1_OAEP.new(key)
        return cipher_rsa.encrypt(bytearray(plaintext, "utf-8"))
    elif algorithm == "DSA / ElG":
        pass
    return ''


def concatanateSignatureAndMessage(keyId, signature, message):
    return keyId + signature + message


def getSessionKey():
    return get_random_bytes(16)


def generateMessage(privateKeyRing, publicKeyRing, email, password, message, assymetricAlgorithm, symmetricAlgorithm):
    privateKeyId = getKeyIdPrivateRing(privateKeyRing, email)
    publicKeyId = getKeyIdPublicRing(publicKeyRing, email)
    encryptedPrivateKey = getEncryptedPrivateKey(privateKeyRing, email)
    publicKey = getPublicKeyPublicRing(publicKeyRing, email)
    hashedPassword = key_util.hashSha1(password)

    privateKey = key_util.decryptPrivateKey(encryptedPrivateKey, hashedPassword, getAlgPrivateRing(privateKeyRing, email))

    hashedMessage = key_util.hashSha1(message)
    encryptedHashedMessage = encryptAsymmetricAuthentication(privateKey, hashedMessage, assymetricAlgorithm)

    signatureMessage = concatanateSignatureAndMessage(privateKeyId, encryptedHashedMessage, message)

    sessionKey = getSessionKey()

    encryptedSignatureAndMessage = encryptSymmetric(sessionKey, signatureMessage, symmetricAlgorithm)

    encryptedSessionKey = encryptAsymmetricSecrecy(publicKey, sessionKey, symmetricAlgorithm)

    return concatanateSignatureAndMessage(publicKeyId, encryptedSessionKey, encryptedSignatureAndMessage)

# print(encryptAsymmetricAuthentication(RSA.import_key(open("receiver.pem").read()), "asdfg0", "RSA"))
