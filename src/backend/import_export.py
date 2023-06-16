from Crypto.PublicKey import DSA
from Crypto.PublicKey import RSA


RESOURCES_PATH = "../../resources/keys/"


def exportPublicKey(keyId, publicKey):
    with open(RESOURCES_PATH + "public/" + str(keyId) + '.pem', 'wb') as f:
        f.write(publicKey.export_key('PEM'))


def exportPrivateKey(keyId, privateKey):
    with open(RESOURCES_PATH + "private/" + str(keyId) + '.pem', 'wb') as f:
        f.write(privateKey)


def importPublicKeyRsa(keyId):
    with open(RESOURCES_PATH + "public/" + str(keyId) + '.pem', 'r') as f:
        return RSA.import_key(f.read())


def importPublicKeyDsa(keyId):
    with open(RESOURCES_PATH + "public/" + str(keyId) + '.pem', 'r') as f:
        return DSA.import_key(f.read())


def importPrivatecKeyRsa(keyId, password):
    with open(RESOURCES_PATH + "private/" + str(keyId) + '.pem', 'r') as f:
        return RSA.import_key(f.read(), passphrase=password)


def importPrivateKeyDsa(keyId, password):
    with open(RESOURCES_PATH + "private/" + str(keyId) + '.pem', 'r') as f:
        return DSA.import_key(f.read(), passphrase=password)
