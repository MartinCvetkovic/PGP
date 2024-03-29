import base64
import time
import zlib
import json
from src.backend.message_receiving import decryptSymmetric

from Crypto.Cipher import DES3, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA, DSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import DSS, PKCS1_v1_5
from elgamal.elgamal import Elgamal, PublicKey

from src.backend import key_util

RESOURCES_PATH = "../../resources/messages/"

def getKeyIdPublicRing(publicRing, email):
    for row in publicRing:
        if row[4] == email:
            return row[2]
    raise Exception("No key id in public ring")


def getPublicKeyPublicRing(publicRing, email):
    for row in publicRing:
        if row[4] == email:
            return row[6]
    raise Exception("No public key in public ring")


def getAlgPrivateRing(privateRing, email):
    for row in privateRing:
        if row[4] == email:
            return row[0]
    raise Exception("No alg in private ring")


def getKeyIdPrivateRing(privateRing, email):
    for row in privateRing:
        if row[4] == email:
            return row[2]
    raise Exception("No key id in private ring")


def getEncryptedPrivateKey(privateRing, email):
    for row in privateRing:
        if row[4] == email:
            return row[7]
    raise Exception("No private key in private ring")


def encryptSymmetric(key, plaintext, algorithm, nonce):
    if algorithm == "TripleDES":
        cipher = DES3.new(key, DES3.MODE_EAX, nonce=nonce)
        # return cipher.iv + cipher.encrypt(bytearray(plaintext, "utf-8")) # mozda ova varijanta radi, ako trenutna nece
        return cipher.encrypt(plaintext)
    elif algorithm == "AES128":
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        return cipher.encrypt_and_digest(plaintext)[0]
    raise Exception("Unsupported symmetric algorithm")


def encryptAsymmetricAuthentication(key, plaintext, algorithm):
    if algorithm[:3] == "RSA":
        hashedMessage = key_util.hashSha1Object(plaintext)
        #cipher_rsa = PKCS1_OAEP.new(key)
        #return cipher_rsa.encrypt(bytearray(hashedMessage, "utf-8"))
        return PKCS1_v1_5.new(key).sign(hashedMessage)
    elif algorithm[:3] == "DSA":
        hashedMessage = key_util.hashSha1Object(plaintext)
        signer = DSS.new(key, 'fips-186-3')
        return signer.sign(hashedMessage)
    raise Exception("Unsupported asymmetric algorithm authentication")


def encryptAsymmetricSecrecy(key, plaintext, algorithm):
    if algorithm[:3] == "RSA":
        cipher_rsa = PKCS1_OAEP.new(key)
        return cipher_rsa.encrypt(plaintext)
    elif algorithm[:3] == "DSA":
        key: DSA.DsaKey
        pk = key.public_key()
        publicKey = PublicKey(pk._key['p']._value, pk._key['g']._value, pk._key['y']._value)
        cipher = Elgamal.encrypt(plaintext, publicKey)
        tup = cipher.get()
        return tup
    raise Exception("Unsupported asymmetric algorithm secrecy")


def concatanateSignatureAndMessage(keyId, signature, message):
    return bytearray(keyId, "utf-8") + signature + bytearray(message, "utf-8")


def getSessionKey():
    return get_random_bytes(16)


def getAlgorithmFromRing(keyRing, email):
    for row in keyRing:
        if row[4] == email:
            return row[0]
    raise Exception("No algorithm in private ring")


def generateMessage(privateKeyRing, publicKeyRing, emailFrom, emailTo, password, message, symmetricAlgorithm):
    privateKeyId = getKeyIdPrivateRing(privateKeyRing, emailFrom)
    publicKeyId = getKeyIdPublicRing(publicKeyRing, emailTo)
    encryptedPrivateKey = getEncryptedPrivateKey(privateKeyRing, emailFrom)
    publicKey = getPublicKeyPublicRing(publicKeyRing, emailTo)
    privateAssymetricAlgorithm = getAlgorithmFromRing(privateKeyRing, emailFrom)
    publicAssymetricAlgorithm = getAlgorithmFromRing(publicKeyRing, emailTo)
    hashedPassword = key_util.hashSha1(password)

    privateKey = key_util.decryptPrivateKey(encryptedPrivateKey, hashedPassword, getAlgPrivateRing(privateKeyRing, emailFrom))

    encryptedHashedMessage = encryptAsymmetricAuthentication(privateKey, message, privateAssymetricAlgorithm)

    signatureMessage = {
        "privateKeyId": privateKeyId,
        "encryptedHashedMessage": encryptedHashedMessage,
        "message": message
    }

    signatureMessage["encryptedHashedMessage"] = base64.encodebytes(signatureMessage["encryptedHashedMessage"]).decode()

    zippedMessage = zlib.compress(bytearray(json.dumps(signatureMessage), "utf-8"))

    sessionKey = getSessionKey()

    nonce = get_random_bytes(16)
    encryptedSignatureAndMessage = encryptSymmetric(sessionKey, zippedMessage, symmetricAlgorithm, nonce)

    encryptedSessionKey = encryptAsymmetricSecrecy(publicKey, sessionKey, publicAssymetricAlgorithm)

    finalMessage = {
        "publicKeyId": publicKeyId,
        "encryptedSessionKey": encryptedSessionKey,
        "symmetricAlgorithm": symmetricAlgorithm,
        "symmetricNonce": nonce,
        "encryptedSignatureAndMessage": encryptedSignatureAndMessage
    }

    if (publicAssymetricAlgorithm[:3] != "DSA"):
        finalMessage['encryptedSessionKey'] = base64.encodebytes(finalMessage['encryptedSessionKey']).decode()
    finalMessage['encryptedSignatureAndMessage'] = base64.encodebytes(finalMessage['encryptedSignatureAndMessage']).decode()
    finalMessage['symmetricNonce'] = base64.encodebytes(finalMessage['symmetricNonce']).decode()



    finalCipher = base64.encodebytes(bytearray(json.dumps(finalMessage), "utf-8"))

    with open(RESOURCES_PATH + str(time.time()) + '.txt', 'wb') as f:
        f.write(finalCipher)

    return finalCipher
