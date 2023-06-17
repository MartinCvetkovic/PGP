from Crypto.PublicKey import DSA
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1
from src.backend.keygen import generate
import src.frontend.layouts as layouts
from datetime import datetime


def extractKey(keyString):
    return keyString[keyString.find("KEY-----") + 10:keyString.find("-----END") - 2]

def extractAttributes(key, keyType, algorithm):
    if (algorithm[:3] == 'RSA'):
        if (keyType == 'public'):
            attributes = {
                'n': key.n,
                'e': key.e
            }
        else:
            attributes = {
                'n': key.n,
                'd': key.d
            }
    elif (algorithm[:3]=='DSA'):
        if (keyType == 'public'):
            attributes = {
                'p': key._key['p']._value,
                'q': key._key['q']._value,
                'g': key._key['g']._value,
                'y': key._key['y']._value
            }
        else:
            attributes = {
                'p': key._key['p']._value,
                'q': key._key['q']._value,
                'g': key._key['g']._value,
                'x': key._key['y']._value
            }
    else:
        return None

    return attributes

def keyId(keyString):
    key = extractKey(keyString)
    return key[-8:]


def generateKeys(alg, length, name, email, password):
    priv, pub = generate(alg, length)
    if alg == "rsa":
        alg = "RSA"
    else:
        alg = "DSA / ElG"
    layouts.privateKeyRows.append(
        [
            alg + " - " + str(length),
            datetime.now(),
            keyId(str(pub.exportKey())),
            str(name),
            str(email),
            password,
            extractKey(str(pub.exportKey())),
            encryptPrivateKey(priv, password),
            pub
        ]
    )
    return


def deleteKey(selectedKeyRow, selectedTable):

    if selectedKeyRow == -1: return
    if selectedTable == 0:
        layouts.privateKeyRows.pop(selectedKeyRow)
    elif selectedTable == 1:
        layouts.publicKeyRows.pop(selectedKeyRow)




def encryptPrivateKey(privateKey, password):
    h = hashSha1(password)
    return privateKey.export_key('PEM', passphrase=h)


def decryptPrivateKey(privateKey, password, alg):
    if (alg[:3] == "RSA"):
        return RSA.import_key(privateKey, passphrase=password)
    else:
        return DSA.import_key(privateKey, passphrase=password)


def readKey(s):
    alg = ""
    if ("PUBLIC") in s:
        print("Public key")
        try:
            key = RSA.import_key(s)
            alg = "RSA"
            return key, alg
        except ValueError:
            try:
                key = DSA.import_key(s)
                alg = "DSA"
                return key, alg
            except ValueError:
                return

    elif ("PRIVATE") in s:
        print("Private key")
        if "BEGIN RSA PRIVATE KEY" in s:
            alg = "RSA"
            return "", alg
        elif "BEGIN ENCRYPTED PRIVATE KEY" in s:
            alg = "DSA"
            return "", alg
    else:
        return "E"


def hashSha1(string):
    h = SHA1.new()
    h.update(bytearray(string, 'utf-8'))
    return h.hexdigest()


def hashSha1Object(string):
    return SHA1.new(bytearray(string, 'utf-8'))
