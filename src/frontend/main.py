import PySimpleGUI as sg
from src.backend import keygen
from datetime import datetime
from math import sqrt, floor
from src.backend import import_export
from src.backend import message_sending

sg.theme('Dark Amber')

# [algoritam,
# timestamp,
# keyId,
# ime,
# email,
# hash(lozinka),
# javni kljuc,
# privatni kljuc enkriptovan u PEM,
# javni kljuc objekat]
privateKeyRows = []

# [algoritam,
# timestamp,
# keyId,
# ime,
# email,
# javni kljuc,
# javni kljuc objekat]
publicKeyRows = []

# 0 - Private, 1 - Public
selectedTable = 0

selectedKeyRow = -1


def extractKey(keyString):
    return keyString[keyString.find("KEY-----") + 10:keyString.find("-----END") - 2]


# Fail, private kljuc ima 800+ char, cak i u 40 redova zauzima ceo ekran
# def formatKey(keyString, charsPerLine):
#     key = extractKey(keyString)
#     for i in range(1, (len(key) // charsPerLine) + 1):
#         key = key[:charsPerLine * i + 2 * (i - 1)] + "\n" + key[charsPerLine * i + 2 * (i - 1):]
#     return key


def keyId(keyString):
    key = extractKey(keyString)
    return key[-8:]


def generateKeys(alg, length, name, email, password):
    priv, pub = keygen.generate(alg, length)
    if alg == "rsa":
        alg = "RSA"
    else:
        alg = "DSA / ElG"
    privateKeyRows.append(
        [
            alg + " - " + str(length),
            datetime.now(),
            keyId(str(pub.exportKey())),
            str(name),
            str(email),
            message_sending.hashSha1(password),
            extractKey(str(pub.exportKey())),

            #extractKey(str(priv.exportKey())) - staro,
            message_sending.encryptPrivateKey(priv, password),

            pub
        ]
    )
    return


def deleteKey():
    global privateKeyRows, publicKeyRows
    if selectedKeyRow == -1: return
    if selectedTable == 0:
        privateKeyRows.pop(selectedKeyRow)
    elif selectedTable == 1:
        publicKeyRows.pop(selectedKeyRow)


# --------------------- Layout prozora --------------------------- #
def openBaseWindow():
    layout = [
        [sg.Button('Kljucevi')],
        [sg.Button('Posalji poruku')],
        [sg.Button('Primi poruku')]
    ]
    return sg.Window('PGP', layout, resizable=True)


def openKeyWindow():
    global selectedTable
    selectedTable = 0
    layout = [
        [
            sg.Button("Privatni prsten", disabled=True, key='-PRBUTTON-'),
            sg.Button("Javni prsten", key='-PUBUTTON-')
        ],
        [
            sg.Button("Prikazi javni kljuc", disabled=True, key='-SHOWPU-'),
            sg.Button("Prikazi privatni kljuc", disabled=True, key='-SHOWPR-')
        ],
        [
            sg.Button("Izvezi javni kljuc", disabled=True, key='-EXPORTPU-'),
            sg.Button("Izvezi privatni kljuc", disabled=True, key='-EXPORTPR-')
        ],
        [
            sg.Button("Generisi novi par kljuceva", button_color=('black', 'green'), key='-KEYGENBUTTON-'),
            sg.Button("Obrisi", disabled=True, button_color=('white', 'red'), key='-KEYDELBUTTON-')
        ],
        [
            sg.Table(headings=['Algoritam', 'Timestamp', 'KeyID', 'Ime', 'Email'],
                     values=privateKeyRows, key='-PRTABLE-', row_height=48, enable_events=True,
                     select_mode=sg.TABLE_SELECT_MODE_BROWSE),
            sg.Table(headings=['Algoritam', 'Timestamp', 'KeyID', 'Ime', 'Email',],
                     values=publicKeyRows, key='-PUTABLE-',
                     visible=False, row_height=48, enable_events=True, select_mode=sg.TABLE_SELECT_MODE_BROWSE)
        ]
    ]
    return sg.Window('Kljucevi', layout, resizable=True)


def openSendWindow():
    layout = [
        [
            sg.Text("Slanje poruke")
        ]
    ]
    return sg.Window('Slanje', layout, resizable=True)


def openReceiveWindow():
    layout = [
        [
            sg.Text("Prijem poruke")
        ]
    ]
    return sg.Window('Prijem', layout, resizable=True)


def openGenWindow():
    layout = [
        [
            sg.Text("Algoritam:"),
            sg.Radio("RSA", "R1", default=True, key='-ALG-'),
            sg.Radio("DSA / ElGamal", "R1", default=False)
        ],
        [
            sg.Text("Velicina kljuca:"),
            sg.Radio("1024", "R2", default=True, key='-LEN-'),
            sg.Radio("2048", "R2", default=False)
        ],
        [
            sg.Text("Ime"),
            sg.InputText(key='-NAME-')
        ],
        [
            sg.Text("Email"),
            sg.InputText(key='-EMAIL-')
        ],
        [
            sg.Text("Lozinka"),
            sg.InputText(key='-PASSWORD-')
        ],
        [
            sg.Button("OK", button_color=('black', 'green')),
            sg.Button("CANCEL", button_color=('white', 'red'))
        ]
    ]
    return sg.Window('Novi par kljuceva', layout, resizable=True)


def openKeyDisplayWindow(key):
    charsPerLine = floor(sqrt(len(key)) * 2.5) + 3
    if (charsPerLine < 28): charsPerLine = 28
    layout = [
        [
            sg.Multiline(
                key,
                size=(charsPerLine, (len(key) // charsPerLine) + 2),
                text_color=sg.theme_text_color(),
                background_color=sg.theme_text_element_background_color(),
                disabled=True
            )
        ],
        [sg.Button("OK", button_color=('black', 'green'))]
    ]
    return sg.Window('Kljuc', layout, resizable=True)


def openPasswordWindow():
    layout = [
        [
            sg.Text("Lozinka:"), sg.InputText(key='-PASSWORD-')
        ],
        [
            sg.Button("OK", button_color=('black', 'green')),
            sg.Button("CANCEL", button_color=('white', 'red'))
        ]
    ]
    return sg.Window("Password", layout, resizable=True)


# -------------------- main --------------------------- #
window = openBaseWindow()

while True:
    event, values = window.read()  # Read the event that happened and the values dictionary
    print(event, values)
    if event == sg.WIN_CLOSED or event == 'Exit':  # If user closed window with X or if user clicked "Exit" button then exit
        break

    # Prozor prsten kljuceva
    if event == 'Kljucevi':
        print('open kljucevi')
        keyWindow = openKeyWindow()
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
                    keyWindow['-PRTABLE-'].update(values=privateKeyRows)
                elif (selectedTable == 1):
                    keyWindow['-PUTABLE-'].update(values=publicKeyRows)
                keyWindow['-KEYDELBUTTON-'].update(disabled=True)
                keyWindow['-SHOWPU-'].update(disabled=True)
                keyWindow['-SHOWPR-'].update(disabled=True)
                keyWindow['-EXPORTPU-'].update(disabled=True)
                keyWindow['-EXPORTPR-'].update(disabled=True)

            # Prikaz javnog kljuca
            elif event == "-SHOWPU-":
                if (selectedTable == 0):
                    keyDisplayWindow = openKeyDisplayWindow(privateKeyRows[selectedKeyRow][6])
                else:
                    keyDisplayWindow = openKeyDisplayWindow(publicKeyRows[selectedKeyRow][5])
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
                passwordWindow = openPasswordWindow()
                match = False
                while True:
                    event, values = passwordWindow.read()  # Read the event that happened and the values dictionary
                    print(event, values)
                    if event == sg.WIN_CLOSED or event == 'CANCEL':  # If user closed window with X or if user clicked "Exit" button then exit
                        passwordWindow.close()
                        break
                    elif event == 'OK':
                        print(values['-PASSWORD-'])
                        if (message_sending.hashSha1(values['-PASSWORD-']) == privateKeyRows[selectedKeyRow][5]): match = True
                        passwordWindow.close()
                        break
                if (match):
                    keyDisplayWindow = openKeyDisplayWindow(extractKey(str(
                        message_sending.decryptPrivateKey(
                            privateKeyRows[selectedKeyRow][7],
                            privateKeyRows[selectedKeyRow][5],
                            privateKeyRows[selectedKeyRow][0])
                    .exportKey())))


                else:
                    keyDisplayWindow = openKeyDisplayWindow("Greska: Pogresna lozinka")
                while True:
                    event, values = keyDisplayWindow.read()  # Read the event that happened and the values dictionary
                    print(event, values)
                    if event == sg.WIN_CLOSED or event == 'OK':  # If user closed window with X or if user clicked "Exit" button then exit
                        keyDisplayWindow.close()
                        break
                keyWindow.un_hide()

            elif event == '-EXPORTPU-':
                if (selectedTable == 0):
                    import_export.exportPublicKey(privateKeyRows[selectedKeyRow][2], privateKeyRows[selectedKeyRow][8])
                else:
                    import_export.exportPublicKey(publicKeyRows[selectedKeyRow][2], publicKeyRows[selectedKeyRow][6])

            elif event == '-EXPORTPR-':
                if (selectedTable == 0):
                    import_export.exportPrivateKey(privateKeyRows[selectedKeyRow][2], privateKeyRows[selectedKeyRow][7])

            # Prozor KeyGen
            elif event == "-KEYGENBUTTON-":
                print("KEYGEN")
                genWindow = openGenWindow()
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
                keyWindow = openKeyWindow()
        window = openBaseWindow()

    # Prozor slanja poruke
    elif event == 'Posalji poruku':
        print('open posalji poruku')
        sendWindow = openSendWindow()
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
        receiveWindow = openReceiveWindow()
        window.hide()
        while True:
            event, values = receiveWindow.read()  # Read the event that happened and the values dictionary
            print(event, values)
            if event == sg.WIN_CLOSED or event == 'Exit':  # If user closed window with X or if user clicked "Exit" button then exit
                receiveWindow.close()
                break
        window.un_hide()

window.close()
