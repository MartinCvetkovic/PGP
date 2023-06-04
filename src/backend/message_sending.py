import base64
import zlib

from Crypto.Cipher import DES3, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA, DSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import DSS
from elgamal.elgamal import Elgamal, PublicKey

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
    raise Exception("Unsupported symmetric algorithm")


def encryptAsymmetricAuthentication(key, plaintext, algorithm):
    if algorithm == "RSA":
        hashedMessage = key_util.hashSha1(plaintext)
        cipher_rsa = PKCS1_OAEP.new(key)
        return cipher_rsa.encrypt(bytearray(hashedMessage, "utf-8"))
    elif algorithm == "DSA / ElG":
        hashedMessage = key_util.hashSha1Object(plaintext)
        signer = DSS.new(key, 'fips-186-3')
        return signer.sign(hashedMessage)
    raise Exception("Unsupported asymmetric algorithm authentication")


def encryptAsymmetricSecrecy(key, plaintext, algorithm):
    if algorithm == "RSA":
        cipher_rsa = PKCS1_OAEP.new(key)
        return cipher_rsa.encrypt(bytearray(plaintext, "utf-8"))
    elif algorithm == "DSA / ElG":
        # TODO elgamal do mojega - pitanje da li radi, ima i greska u biblioteci, sve je pod znakom pitanja, ali nema bolje
        key: DSA.DsaKey
        p, g, y = key.domain()
        publicKey = PublicKey(p, g, y)
        cipher = Elgamal.encrypt(bytearray(plaintext, "utf-8"), publicKey)
        return cipher.get()
    raise Exception("Unsupported asymmetric algorithm secrecy")


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

    privateKey = key_util.decryptPrivateKey(encryptedPrivateKey, hashedPassword,
                                            getAlgPrivateRing(privateKeyRing, email))

    encryptedHashedMessage = encryptAsymmetricAuthentication(privateKey, message, assymetricAlgorithm)

    signatureMessage = concatanateSignatureAndMessage(privateKeyId, encryptedHashedMessage, message)

    zippedMessage = zlib.compress(signatureMessage)

    sessionKey = getSessionKey()

    encryptedSignatureAndMessage = encryptSymmetric(sessionKey, zippedMessage, symmetricAlgorithm)

    encryptedSessionKey = encryptAsymmetricSecrecy(publicKey, sessionKey, symmetricAlgorithm)

    finalMessage = concatanateSignatureAndMessage(publicKeyId, encryptedSessionKey, encryptedSignatureAndMessage)
    return base64.encodebytes(bytearray(finalMessage, "utf-8"))

# print(encryptAsymmetricSecrecy(
#     DSA.import_key(open("../../resources/zWkbyA==.pem").read(), passphrase=key_util.hashSha1("a")),
#     "asdfg0",
#     "DSA / ElG")
# )
