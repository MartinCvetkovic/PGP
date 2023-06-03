from Crypto.PublicKey import DSA
from Crypto.PublicKey import RSA


RESOURCES_PATH = "../../resources/"


def exportPublicKey(keyId, publicKey):
    with open(RESOURCES_PATH + str(keyId) + '.pem', 'wb') as f:
        f.write(publicKey.export_key('PEM'))


def exportPrivateKey(keyId, privateKey, password):
    with open(RESOURCES_PATH + str(keyId) + '.pem', 'wb') as f:
        f.write(privateKey.export_key('PEM', password))


def importPublicKeyRsa(keyId):
    with open(RESOURCES_PATH + str(keyId) + '.pem', 'r') as f:
        return RSA.import_key(f.read())


def importPublicKeyDsa(keyId):
    with open(RESOURCES_PATH + str(keyId) + '.pem', 'r') as f:
        return DSA.import_key(f.read())


def importPrivatecKeyRsa(keyId, password):
    with open(RESOURCES_PATH + str(keyId) + '.pem', 'r') as f:
        return RSA.import_key(f.read(), passphrase=password)


def importPrivateKeyDsa(keyId, password):
    with open(RESOURCES_PATH + str(keyId) + '.pem', 'r') as f:
        return DSA.import_key(f.read(), passphrase=password)
