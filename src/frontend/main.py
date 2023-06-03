import PySimpleGUI as sg

import src.backend.key_util
from datetime import datetime
from src.backend import import_export
from src.backend import key_util
import src.frontend.layouts as layouts

sg.theme('Dark Amber')

# 0 - Private, 1 - Public
selectedTable = 0
selectedKeyRow = -1

# -------------------- main --------------------------- #
window = layouts.openBaseWindow()

while True:
    event, values = window.read()
    print(event, values)
    if event == sg.WIN_CLOSED or event == 'Exit':
        break

    # Prozor prsten kljuceva
    if event == 'Kljucevi':
        print('open kljucevi')
        keyWindow = layouts.openKeyWindow()
        selectedTable = 0
        window.close()
        while True:
            event, values = keyWindow.read()
            print(event, values)
            if event == sg.WIN_CLOSED or event == 'Exit':
                keyWindow.close()
                break

            #Prikaz prstena javnih kljuceva
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

            #Prikaz prstena privatnih kljuceva
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

            #Select reda iz tabele privatnih kljuceva
            elif event == "-PRTABLE-":
                print("private click")
                if (len(values[event]) == 0): continue
                selectedKeyRow = values[event][0]
                keyWindow['-KEYDELBUTTON-'].update(disabled=False)
                keyWindow['-SHOWPU-'].update(disabled=False)
                keyWindow['-SHOWPR-'].update(disabled=False)
                keyWindow['-EXPORTPU-'].update(disabled=False)
                keyWindow['-EXPORTPR-'].update(disabled=False)

            #Select reda iz tabele javnih kljuceva
            elif event == "-PUTABLE-":
                print("public click")
                if (len(values[event]) == 0): continue
                selectedKeyRow = values[event][0]
                keyWindow['-KEYDELBUTTON-'].update(disabled=False)
                keyWindow['-SHOWPU-'].update(disabled=False)
                keyWindow['-EXPORTPU-'].update(disabled=False)

            #Brisanje kluca
            elif event == "-KEYDELBUTTON-":
                key_util.deleteKey(selectedKeyRow, selectedTable)
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
                    event, values = keyDisplayWindow.read()
                    print(event, values)
                    if event == sg.WIN_CLOSED or event == 'OK':
                        keyDisplayWindow.close()
                        break
                keyWindow.un_hide()

            # Prikaz privatnog kluca
            elif event == "-SHOWPR-":
                keyWindow.hide()
                passwordWindow = layouts.openPasswordWindow()
                match = False
                while True:
                    event, values = passwordWindow.read()
                    print(event, values)
                    if event == sg.WIN_CLOSED or event == 'CANCEL':
                        passwordWindow.close()
                        break
                    elif event == 'OK':
                        print(values['-PASSWORD-'])
                        if (src.backend.key_util.hashSha1(values['-PASSWORD-']) == layouts.privateKeyRows[selectedKeyRow][5]): match = True
                        passwordWindow.close()
                        break

                #Ispravna lozinka
                if (match):
                    keyDisplayWindow = layouts.openKeyDisplayWindow(key_util.extractKey(str(
                        key_util.decryptPrivateKey(
                            layouts.privateKeyRows[selectedKeyRow][7],
                            layouts.privateKeyRows[selectedKeyRow][5],
                            layouts.privateKeyRows[selectedKeyRow][0])
                    .exportKey())))
                #Pogresna lozinka
                else:
                    keyDisplayWindow = layouts.openKeyDisplayWindow("Greska: Pogresna lozinka")
                while True:
                    event, values = keyDisplayWindow.read()
                    print(event, values)
                    if event == sg.WIN_CLOSED or event == 'OK':
                        keyDisplayWindow.close()
                        break
                keyWindow.un_hide()

            #Izvoz javnog kluca
            elif event == '-EXPORTPU-':
                if (selectedTable == 0):
                    import_export.exportPublicKey(layouts.privateKeyRows[selectedKeyRow][2], layouts.privateKeyRows[selectedKeyRow][8])
                else:
                    import_export.exportPublicKey(layouts.publicKeyRows[selectedKeyRow][2], layouts.publicKeyRows[selectedKeyRow][6])

            #Izvoz privatnog kljuca
            elif event == '-EXPORTPR-':
                if (selectedTable == 0):
                    import_export.exportPrivateKey(layouts.privateKeyRows[selectedKeyRow][2], layouts.privateKeyRows[selectedKeyRow][7])

            #Uvoz kluca
            elif event == '-IMPORTINPUT-':
                print("a")
                with open(values['-IMPORT-']) as f:
                    tip = ""
                    keyWindow.close()
                    if (f == None): continue
                    s = f.read()
                    key, alg = key_util.readKey(s)
                    print("Key: " + str(key) + "\nAlgorithm: " + alg)

                    #Uvoz privanog kljuca
                    if (str(key) == ""):
                        tip = "PR"
                        keyWindow.close()
                        match = False
                        passwordWindow = layouts.openPasswordWindow()
                        while True:
                            event, values = passwordWindow.read()
                            print(event, values)
                            if event == sg.WIN_CLOSED or event == 'CANCEL':
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
                        else:
                            keyDisplayWindow = layouts.openKeyDisplayWindow("Greska: Pogresna lozinka")
                            while True:
                                event, values = keyDisplayWindow.read()
                                print(event, values)
                                if event == sg.WIN_CLOSED or event == 'OK':
                                    keyDisplayWindow.close()
                                    break

                    #Uvoz javnog kljuca
                    else:
                        tip = "PU"

                    #Input imena i email-a od korisnika
                    if (str(key) != ""):
                        credsWindow = layouts.openCredWindow()
                        while True:
                            event, values = credsWindow.read()
                            print(event, values)
                            if event == sg.WIN_CLOSED or event == 'CANCEL':
                                credsWindow.close()
                                break
                            elif event == "OK":
                                ime = values['-NAME-']
                                email = values['-EMAIL-']

                                #Ubacivanje kljuca u prsten kljuceva
                                if (tip == "PR"):
                                    layouts.privateKeyRows.append([
                                        alg,
                                        datetime.now(),
                                        key_util.keyId(str(key.public_key().exportKey())),
                                        ime,
                                        email,
                                        key_util.hashSha1(p),
                                        key_util.extractKey(str(key.public_key().exportKey())),
                                        key_util.encryptPrivateKey(key, p),
                                        key.public_key()
                                    ])
                                elif (tip == "PU"):
                                    layouts.publicKeyRows.append([
                                        alg,
                                        datetime.now(),
                                        key_util.keyId(str(key.exportKey())),
                                        ime,
                                        email,
                                        key_util.extractKey(str(key.exportKey())),
                                        key
                                    ])
                                credsWindow.close()
                                break
                    keyWindow = layouts.openKeyWindow()
                    selectedTable = 0

            # Prozor KeyGen
            elif event == "-KEYGENBUTTON-":
                print("KEYGEN")
                genWindow = layouts.openGenWindow()
                keyWindow.close()
                while True:
                    event, values = genWindow.read()
                    print(event, values)
                    if event == sg.WIN_CLOSED or event == 'CANCEL':
                        genWindow.close()
                        break
                    if event == 'OK':
                        print(values['-PASSWORD-'])
                        key_util.generateKeys("rsa" if values["-ALG-"] else "dsa", 1024 if values['-LEN-'] else 2048,
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
            event, values = sendWindow.read()
            print(event, values)
            if event == sg.WIN_CLOSED or event == 'Exit':
                sendWindow.close()
                break

        window.un_hide()

    # Prozor prijema poruke
    elif event == 'Primi poruku':
        print('open primi poruku')
        receiveWindow = layouts.openReceiveWindow()
        window.hide()
        while True:
            event, values = receiveWindow.read()
            print(event, values)
            if event == sg.WIN_CLOSED or event == 'Exit':
                receiveWindow.close()
                break
        window.un_hide()

window.close()
