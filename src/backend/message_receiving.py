from base64 import decodebytes
import ast
import json

def decodeMessage(path):
    with open(path, 'rb') as f:
        m = decodebytes(f.read()).decode(encoding='utf-8')
        print(m)
        #finalMessage = ast.literal_eval(m)
        #finalMessage = json.loads(m)


        return m