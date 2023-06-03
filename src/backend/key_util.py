from Crypto.PublicKey import DSA
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1


def encryptPrivateKey(privateKey, password):
    h = hashSha1(password)
    return privateKey.export_key('PEM', passphrase=h)


def decryptPrivateKey(privateKey, password, alg):
    if (alg[:3] == "RSA"):
        return RSA.import_key(privateKey, passphrase=password)
    else:
        return DSA.import_key(privateKey, passphrase=password)


def readKey(file):
    s = file.read()
    if ("PUBLIC") in s:
        print("Public key")
        try:
            key = RSA.import_key(s)
            alg = "RSA"
        except ValueError:
            try:
                key = DSA.import_key(s)
                alg = "DSA"
            except ValueError:
                return

    elif ("PRIVATE") in s:
        print("Private key")
        if "BEGIN RSA PRIVATE KEY" in s:
            alg = "RSA"

        elif "BEGIN ENCRYPTED PRIVATE KEY" in s:
            alg = "DSA"

    else: return
    print("Algorithm")


def hashSha1(string):
    h = SHA1.new()
    h.update(bytearray(string, 'utf-8'))
    return h.hexdigest()
