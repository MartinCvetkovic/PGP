from base64 import decodebytes
import ast
import base64
import json
from src.backend.key_util import decryptPrivateKey, hashSha1, hashSha1Object

import time
import zlib

from Crypto.Cipher import DES3, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA, DSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import DSS, PKCS1_v1_5
from elgamal.elgamal import Elgamal, PrivateKey

from src.frontend.layouts import privateKeyRows, publicKeyRows

def decryptAsymmetricSecrecy(key, ciphertext, algorithm):
    if algorithm[:3] == "RSA":
        cipher_rsa = PKCS1_OAEP.new(key)
        return cipher_rsa.decrypt(ciphertext)
    elif algorithm[:3] == "DSA":
        # TODO elgamal do mojega - pitanje da li radi, ima i greska u biblioteci, sve je pod znakom pitanja, ali nema bolje
        key: DSA.DsaKey
        p, g, y = key.domain()
        privateKey = PrivateKey(p, g, y)
        plain = Elgamal.decrypt(ciphertext, privateKey)
        return plain.get()
    raise Exception("Unsupported asymmetric algorithm secrecy")


def decryptSymmetric(key, ciphertext, algorithm, nonce):
    if algorithm == "TripleDES":
        cipher = DES3.new(key, DES3.MODE_EAX, nonce=nonce)
        # return cipher.iv + cipher.decrypt(bytearray(plaintext, "utf-8")) # mozda ova varijanta radi, ako trenutna nece
        return cipher.decrypt(ciphertext)
    elif algorithm == "AES128":
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt(ciphertext)
    raise Exception("Unsupported symmetric algorithm")


def validateAsymmetricAuthentication(key, plaintext, algorithm, signature):
    if algorithm[:3] == "RSA":
        hashedMessage = hashSha1Object(plaintext)
        try:
            PKCS1_v1_5.new(key).verify(hashedMessage, signature)
            return True
        except (ValueError, TypeError):
            return False
        #cipher_rsa = PKCS1_OAEP.new(key)
        #return (cipher_rsa.decrypt(cipherSignature) == hashedMessage)
    elif algorithm[:3] == "DSA":
        hashedMessage = hashSha1Object(plaintext)
        verifier = DSS.new(key, 'fips-186-3')
        try:
            verifier.verify(hashedMessage, signature)
            return True
        except ValueError:
            return False
    raise Exception("Unsupported asymmetric algorithm authentication")


def decodeMessage(path):
    with open(path, 'rb') as f:
        fileString = decodebytes(f.read()).decode(encoding='utf-8')
        try:
            finalMessage = json.loads(fileString)
        except json.decoder.JSONDecodeError:
            return "Greska: Poruka je koruptovana."
        finalMessage['encryptedSessionKey'] = base64.decodebytes(bytearray(finalMessage['encryptedSessionKey'], "utf-8"))
        finalMessage['encryptedSignatureAndMessage'] = base64.decodebytes(bytearray(finalMessage['encryptedSignatureAndMessage'], "utf-8"))
        finalMessage['symmetricNonce'] = base64.decodebytes(bytearray(finalMessage['symmetricNonce'], "utf-8"))

        #Trazenje privatnog kljuca za dekripciju sesijskog
        encryptedPrivateKey = "";
        password = ""
        asymmetricAlgorithm = ""
        symmetricAlgorithm = finalMessage['symmetricAlgorithm']
        symmetricNonce = finalMessage['symmetricNonce']

        for row in privateKeyRows:
            if (row[2] == finalMessage['publicKeyId']):
                encryptedPrivateKey = row[7]
                password = row[5]
                asymmetricAlgorithm = row[0]
                break

        if (encryptedPrivateKey == ""):
            return "Greska: Nemate odgovarajuci privatni kljuc za dekripciju sesijskog kljuca"

        #Dekripcija privatnog i sesijskog kljuca
        privateKey = decryptPrivateKey(encryptedPrivateKey, hashSha1(password), asymmetricAlgorithm)
        sessionKey = decryptAsymmetricSecrecy(privateKey, finalMessage['encryptedSessionKey'], asymmetricAlgorithm)

        #Dekriptovanje i unzipovanje signatureMessage pomocu sesijskog kljuca
        zippedMessage = decryptSymmetric(sessionKey, finalMessage['encryptedSignatureAndMessage'], symmetricAlgorithm, symmetricNonce)
        try:
            signatureMessage = json.loads(zlib.decompress(zippedMessage))
        except (json.decoder.JSONDecodeError, zlib.error):
            return "Greska: Poruka je koruptovana."

        signatureMessage['encryptedHashedMessage'] = base64.decodebytes(bytearray(signatureMessage['encryptedHashedMessage'], "utf-8"))

        # Trazenje javnog kljuca za proveru potpisa
        validated = True
        publicKey = ""
        asymmetricAlgorithm = ""
        message = signatureMessage['message']
        encryptedSignature = signatureMessage['encryptedHashedMessage']

        for row in publicKeyRows:
            if (row[2] == signatureMessage['privateKeyId']):
                publicKey = row[6]
                asymmetricAlgorithm = row[0]
                validated = False
                break

        #Provera potpisa
        if (validated):
            return ("Greska: Nemate odgovarajuci javni kljuc za proveru potpisa poruke\n========================\n"+message)
        else:
            validated = validateAsymmetricAuthentication(publicKey, message, asymmetricAlgorithm, encryptedSignature)

        return (("Poruka je ispravno potpisana\n========================\n"+message) if validated else ("PORUKA NIJE ISPRAVNO POTPISANA\n========================\n"+message))