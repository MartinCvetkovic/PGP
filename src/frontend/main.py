import PySimpleGUI as sg
from src.backend import keygen
from datetime import datetime

sg.theme('Dark Amber')

privateKeyRows = []
publicKeyRows = []

#0 - Private, 1 - Public
selectedTable = 0

selectedKeyRow = -1

#Fail, private kljuc ima 800+ char, cak i u 40 redova zauzima ceo ekran
def formatKey(keyString, charsPerLine):
    key = keyString[keyString.find("KEY-----")+10:keyString.find("-----END")-2]
    for i in range(1,len(key)//charsPerLine):
        key = key[:charsPerLine*i+2*(i-1)]+"\n"+key[charsPerLine*i+2*(i-1):]
    return key

def keyId(keyString):
    key = keyString[keyString.find("KEY-----") + 10:keyString.find("-----END") - 2]
    return key[-63:-42]+"\n"+key[-42:-21]+"\n"+key[-21:]

def generateKeys(alg, length, name, email):
    priv, pub = keygen.generate(alg, length)
    privateKeyRows.append([alg, datetime.now(), keyId(str(pub.exportKey())), "WIP", "WIP", str(name), str(email)])
    return

def deleteKey():
    global privateKeyRows, publicKeyRows
    if (selectedKeyRow == -1): return
    if (selectedTable == 0): privateKeyRows.pop(selectedKeyRow)
    elif (selectedTable == 1): publicKeyRows.pop(selectedKeyRow)

def openBaseWindow():
    layout = [
        [sg.Button('Kljucevi')],
        [sg.Button('Posalji poruku')],
        [sg.Button('Primi poruku')]
    ]
    return sg.Window('PGP', layout)


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
            sg.Button("Generisi novi par kljuceva", button_color=('black', 'green'), key='-KEYGENBUTTON-'),
            sg.Button("Obrisi", disabled=True, button_color=('white', 'red'), key='-KEYDELBUTTON-')
        ],
        [
            sg.Table(headings=['Algoritam', 'Timestamp', 'KeyID', 'Javni Kljuc', 'Privatni Kljuc', 'Ime', 'Email'],
                     values=privateKeyRows, key='-PRTABLE-', row_height=48, enable_events=True, select_mode=sg.TABLE_SELECT_MODE_BROWSE),
            sg.Table(headings=['Algoritam', 'Timestamp', 'KeyID', 'Javni Kljuc', 'Vera u Vlasnika', 'Ime', 'Email',
                               'Legitimitet', 'Potpis(i)', 'Vere u potpis(e)'], values=publicKeyRows, key='-PUTABLE-',
                     visible=False, row_height=48, enable_events=True, select_mode=sg.TABLE_SELECT_MODE_BROWSE)
        ]
    ]
    return sg.Window('Kljucevi', layout)


def openSendWindow():
    layout = [
        [
            sg.Text("Slanje poruke")
        ]
    ]
    return sg.Window('Slanje', layout)


def openReceiveWindow():
    layout = [
        [
            sg.Text("Prijem poruke")
        ]
    ]
    return sg.Window('Prijem', layout)


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
            sg.Button("OK", button_color=('black', 'green')),
            sg.Button("CANCEL", button_color=('white', 'red'))
        ]
    ]
    return sg.Window('Novi par kljuceva', layout)

def openKeyDisplayWindow(key):
    layout = [
        [sg.Text(key)],
        [sg.Button("OK", button_color=('black', 'green'))]
    ]

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

                selectedKeyRow = -1
                keyWindow['-KEYDELBUTTON-'].update(disabled=True)
                keyWindow['-SHOWPU-'].update(disabled=True)
                keyWindow['-SHOWPR-'].update(disabled=True)
                keyWindow['-PUTABLE-'].update(select_rows=[])
                keyWindow['-PRTABLE-'].update(select_rows=[])


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
            elif event == "-PUTABLE-":
                print("public click")
                if (len(values[event]) == 0): continue
                selectedKeyRow = values[event][0]
                keyWindow['-KEYDELBUTTON-'].update(disabled=False)
                keyWindow['-SHOWPU-'].update(disabled=False)
                keyWindow['-SHOWPR-'].update(disabled=False)
            elif event == "-KEYDELBUTTON-":
                deleteKey()
                if (selectedTable == 0): keyWindow['-PRTABLE-'].update(values=privateKeyRows)
                elif (selectedTable == 1): keyWindow['-PUTABLE-'].update(values=publicKeyRows)

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
                        generateKeys("rsa" if values["-ALG-"] else "dsa", 1024 if values['-LEN-'] else 2048,
                                     values['-NAME-'], values['-EMAIL-'])
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
