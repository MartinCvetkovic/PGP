import PySimpleGUI as sg

import src.backend.key_util
from src.backend import keygen
from datetime import datetime
from src.backend import import_export
from src.backend import key_util
import src.frontend.layouts as layouts

sg.theme('Dark Amber')

# 0 - Private, 1 - Public
selectedTable = 0
selectedKeyRow = -1


def extractKey(keyString):
    return keyString[keyString.find("KEY-----") + 10:keyString.find("-----END") - 2]


def keyId(keyString):
    key = extractKey(keyString)
    return key[-8:]


def generateKeys(alg, length, name, email, password):
    priv, pub = keygen.generate(alg, length)
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
            src.backend.key_util.hashSha1(password),
            extractKey(str(pub.exportKey())),
            key_util.encryptPrivateKey(priv, password),
            pub
        ]
    )
    return


def deleteKey():

    if selectedKeyRow == -1: return
    if selectedTable == 0:
        layouts.privateKeyRows.pop(selectedKeyRow)
    elif selectedTable == 1:
        layouts.publicKeyRows.pop(selectedKeyRow)




# -------------------- main --------------------------- #
window = layouts.openBaseWindow()

while True:
    event, values = window.read()  # Read the event that happened and the values dictionary
    print(event, values)
    if event == sg.WIN_CLOSED or event == 'Exit':  # If user closed window with X or if user clicked "Exit" button then exit
        break

    # Prozor prsten kljuceva
    if event == 'Kljucevi':
        print('open kljucevi')
        keyWindow = layouts.openKeyWindow()
        selectedTable = 0
        window.close()
        while True:
            event, values = keyWindow.read()  # Read the event that happened and the values dictionary
            print(event, values)
            if event == sg.WIN_CLOSED or event == 'Exit':  # If user closed window with X or if user clicked "Exit" button then exit
                keyWindow.close()
                break

            if event == "-PUBUTTON-":
                selectedTable = 1
                keyWindow["-PUTABLE-"].update(visible=True)
                keyWindow["-PRTABLE-"].update(visible=False)
                keyWindow["-PUBUTTON-"].update(disabled=True)
                keyWindow["-PRBUTTON-"].update(disabled=False)
                keyWindow['-EXPORTPU-'].update(disabled=True)
                keyWindow['-EXPORTPR-'].update(disabled=True)

                selectedKeyRow = -1
                keyWindow['-KEYDELBUTTON-'].update(disabled=True)
                keyWindow['-SHOWPU-'].update(disabled=True)
                keyWindow['-SHOWPR-'].update(disabled=True)
                keyWindow['-PUTABLE-'].update(select_rows=[])
                keyWindow['-PRTABLE-'].update(select_rows=[])
                keyWindow['-EXPORTPU-'].update(disabled=True)
                keyWindow['-EXPORTPR-'].update(disabled=True)

            elif event == "-PRBUTTON-":
                selectedTable = 0
                keyWindow["-PUTABLE-"].update(visible=False)
                keyWindow["-PRTABLE-"].update(visible=True)
                keyWindow["-PUBUTTON-"].update(disabled=False)
                keyWindow["-PRBUTTON-"].update(disabled=True)

                selectedKeyRow = -1
                keyWindow['-KEYDELBUTTON-'].update(disabled=True)
                keyWindow['-SHOWPU-'].update(disabled=True)
                keyWindow['-SHOWPR-'].update(disabled=True)

            elif event == "-PRTABLE-":
                print("private click")
                if (len(values[event]) == 0): continue
                selectedKeyRow = values[event][0]
                keyWindow['-KEYDELBUTTON-'].update(disabled=False)
                keyWindow['-SHOWPU-'].update(disabled=False)
                keyWindow['-SHOWPR-'].update(disabled=False)
                keyWindow['-EXPORTPU-'].update(disabled=False)
                keyWindow['-EXPORTPR-'].update(disabled=False)

            elif event == "-PUTABLE-":
                print("public click")
                if (len(values[event]) == 0): continue
                selectedKeyRow = values[event][0]
                keyWindow['-KEYDELBUTTON-'].update(disabled=False)
                keyWindow['-SHOWPU-'].update(disabled=False)
                keyWindow['-EXPORTPU-'].update(disabled=False)

            elif event == "-KEYDELBUTTON-":
                deleteKey()
                if (selectedTable == 0):
                    keyWindow['-PRTABLE-'].update(values=layouts.privateKeyRows)
                elif (selectedTable == 1):
                    keyWindow['-PUTABLE-'].update(values=layouts.publicKeyRows)
                keyWindow['-KEYDELBUTTON-'].update(disabled=True)
                keyWindow['-SHOWPU-'].update(disabled=True)
                keyWindow['-SHOWPR-'].update(disabled=True)
                keyWindow['-EXPORTPU-'].update(disabled=True)
                keyWindow['-EXPORTPR-'].update(disabled=True)

            # Prikaz javnog kljuca
            elif event == "-SHOWPU-":
                if (selectedTable == 0):
                    keyDisplayWindow = layouts.openKeyDisplayWindow(layouts.privateKeyRows[selectedKeyRow][6])
                else:
                    keyDisplayWindow = layouts.openKeyDisplayWindow(layouts.publicKeyRows[selectedKeyRow][5])
                keyWindow.hide()
                while True:
                    event, values = keyDisplayWindow.read()  # Read the event that happened and the values dictionary
                    print(event, values)
                    if event == sg.WIN_CLOSED or event == 'OK':  # If user closed window with X or if user clicked "Exit" button then exit
                        keyDisplayWindow.close()
                        break
                keyWindow.un_hide()

            # Prikaz privatnog kluca
            elif event == "-SHOWPR-":
                keyWindow.hide()
                passwordWindow = layouts.openPasswordWindow()
                match = False
                while True:
                    event, values = passwordWindow.read()  # Read the event that happened and the values dictionary
                    print(event, values)
                    if event == sg.WIN_CLOSED or event == 'CANCEL':  # If user closed window with X or if user clicked "Exit" button then exit
                        passwordWindow.close()
                        break
                    elif event == 'OK':
                        print(values['-PASSWORD-'])
                        if (src.backend.key_util.hashSha1(values['-PASSWORD-']) == layouts.privateKeyRows[selectedKeyRow][5]): match = True
                        passwordWindow.close()
                        break
                if (match):
                    keyDisplayWindow = layouts.openKeyDisplayWindow(extractKey(str(
                        key_util.decryptPrivateKey(
                            layouts.privateKeyRows[selectedKeyRow][7],
                            layouts.privateKeyRows[selectedKeyRow][5],
                            layouts.privateKeyRows[selectedKeyRow][0])
                    .exportKey())))


                else:
                    keyDisplayWindow = layouts.openKeyDisplayWindow("Greska: Pogresna lozinka")
                while True:
                    event, values = keyDisplayWindow.read()  # Read the event that happened and the values dictionary
                    print(event, values)
                    if event == sg.WIN_CLOSED or event == 'OK':  # If user closed window with X or if user clicked "Exit" button then exit
                        keyDisplayWindow.close()
                        break
                keyWindow.un_hide()

            elif event == '-EXPORTPU-':
                if (selectedTable == 0):
                    import_export.exportPublicKey(layouts.privateKeyRows[selectedKeyRow][2], layouts.privateKeyRows[selectedKeyRow][8])
                else:
                    import_export.exportPublicKey(layouts.publicKeyRows[selectedKeyRow][2], layouts.publicKeyRows[selectedKeyRow][6])

            elif event == '-EXPORTPR-':
                if (selectedTable == 0):
                    import_export.exportPrivateKey(layouts.privateKeyRows[selectedKeyRow][2], layouts.privateKeyRows[selectedKeyRow][7])

            elif event == '-IMPORTINPUT-':
                print("a")
                with open(values['-IMPORT-']) as f:
                    tip = ""
                    keyWindow.close()
                    if (f == None): continue
                    s = f.read()
                    key, alg = key_util.readKey(s)
                    print("Key: " + str(key) + "\nAlgorithm: " + alg)
                    if (str(key) == ""):
                        tip = "PR"
                        keyWindow.close()
                        match = False
                        passwordWindow = layouts.openPasswordWindow()
                        while True:
                            event, values = passwordWindow.read()  # Read the event that happened and the values dictionary
                            print(event, values)
                            if event == sg.WIN_CLOSED or event == 'CANCEL':  # If user closed window with X or if user clicked "Exit" button then exit
                                passwordWindow.close()
                                break
                            elif event == 'OK':
                                try:
                                    p = values['-PASSWORD-']
                                    key = key_util.decryptPrivateKey(s, key_util.hashSha1(p), alg)
                                    match = True
                                except ValueError:
                                    key = ""
                                passwordWindow.close()
                                break
                        if (match):
                            print(str(key.exportKey()))
                            print(str(key.public_key().exportKey()))

                            #keyWindow['-PRTABLE-'].update(values=layouts.privateKeyRows)
                        else:
                            keyDisplayWindow = layouts.openKeyDisplayWindow("Greska: Pogresna lozinka")
                            while True:
                                event, values = keyDisplayWindow.read()  # Read the event that happened and the values dictionary
                                print(event, values)
                                if event == sg.WIN_CLOSED or event == 'OK':  # If user closed window with X or if user clicked "Exit" button then exit
                                    keyDisplayWindow.close()
                                    break
                    else:
                        tip = "PU"


                    if (str(key) != ""):
                        credsWindow = layouts.openCredWindow()
                        while True:
                            event, values = credsWindow.read()  # Read the event that happened and the values dictionary
                            print(event, values)
                            if event == sg.WIN_CLOSED or event == 'CANCEL':  # If user closed window with X or if user clicked "Exit" button then exit
                                credsWindow.close()
                                break
                            elif event == "OK":
                                ime = values['-NAME-']
                                email = values['-EMAIL-']
                                if (tip == "PR"):
                                    layouts.privateKeyRows.append([
                                        alg,
                                        datetime.now(),
                                        keyId(str(key.public_key().exportKey())),
                                        ime,
                                        email,
                                        key_util.hashSha1(p),
                                        extractKey(str(key.public_key().exportKey())),
                                        key_util.encryptPrivateKey(key, p),
                                        key.public_key()
                                    ])
                                elif (tip == "PU"):
                                    layouts.publicKeyRows.append([
                                        alg,
                                        datetime.now(),
                                        keyId(str(key.exportKey())),
                                        ime,
                                        email,
                                        extractKey(str(key.exportKey())),
                                        key
                                    ])
                                credsWindow.close()
                                break
                    keyWindow = layouts.openKeyWindow()
                    selectedTable = 0
                    #keyWindow['-PUTABLE-'].update(values=layouts.publicKeyRows)


            # Prozor KeyGen
            elif event == "-KEYGENBUTTON-":
                print("KEYGEN")
                genWindow = layouts.openGenWindow()
                keyWindow.close()
                while True:
                    event, values = genWindow.read()  # Read the event that happened and the values dictionary
                    print(event, values)
                    if event == sg.WIN_CLOSED or event == 'CANCEL':  # If user closed window with X or if user clicked "Exit" button then exit
                        genWindow.close()
                        break
                    if event == 'OK':
                        print(values['-PASSWORD-'])
                        generateKeys("rsa" if values["-ALG-"] else "dsa", 1024 if values['-LEN-'] else 2048,
                                     values['-NAME-'], values['-EMAIL-'], values['-PASSWORD-'])
                        genWindow.close()
                        break
                keyWindow = layouts.openKeyWindow()
                selectedTable = 0

        window = layouts.openBaseWindow()

    # Prozor slanja poruke
    elif event == 'Posalji poruku':
        print('open posalji poruku')
        sendWindow = layouts.openSendWindow()
        window.hide()
        while True:
            event, values = sendWindow.read()  # Read the event that happened and the values dictionary
            print(event, values)
            if event == sg.WIN_CLOSED or event == 'Exit':  # If user closed window with X or if user clicked "Exit" button then exit
                sendWindow.close()
                break

        window.un_hide()

    # Prozor prijema poruke
    elif event == 'Primi poruku':
        print('open primi poruku')
        receiveWindow = layouts.openReceiveWindow()
        window.hide()
        while True:
            event, values = receiveWindow.read()  # Read the event that happened and the values dictionary
            print(event, values)
            if event == sg.WIN_CLOSED or event == 'Exit':  # If user closed window with X or if user clicked "Exit" button then exit
                receiveWindow.close()
                break
        window.un_hide()

window.close()
