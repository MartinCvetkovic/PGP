from base64 import decodebytes
import ast
import base64
import json

def decodeMessage(path):
    with open(path, 'rb') as f:
        m = decodebytes(f.read()).decode(encoding='utf-8')

        finalMessage = json.loads(m)
        finalMessage['encryptedSessionKey'] = base64.decodebytes(bytearray(finalMessage['encryptedSessionKey'], "utf-8"))
        finalMessage['encryptedSignatureAndMessage'] = base64.decodebytes(bytearray(finalMessage['encryptedSignatureAndMessage'], "utf-8"))

        print(m)
        return m