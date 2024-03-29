import PySimpleGUI as sg
from math import sqrt, floor

# [algoritam,
# timestamp,
# keyId,
# ime,
# email,
# lozinka,
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


def openBaseWindow():
    layout = [
        [sg.Text("")],
        [sg.Text(""),sg.Button('              Kljucevi               ', key='Kljucevi'),sg.Text("")],
        [sg.Text("")],
        [sg.Text(""),sg.Button('          Posalji poruku          ', key='Posalji poruku'),sg.Text("")],
        [
            sg.Text(""),sg.FileBrowse('           Primi poruku           ', file_types=(("Text Files", "*.txt"),), key='Primi poruku', target='-RECEIVEMSG-'),sg.Text(""),
            sg.Input(key='-RECEIVEMSG-', enable_events=True, visible=False)
        ],
        [sg.Text("")]
    ]
    return sg.Window('PGP', layout, resizable=False)


def openKeyWindow():
    global selectedTable
    global privateKeyRows
    global publicKeyRows
    layout = [
        [
            sg.Button("     Privatni prsten     ", disabled=True, key='-PRBUTTON-'),
            sg.Button("         Javni prsten         ", key='-PUBUTTON-')
        ],
        [
            sg.Button("   Prikazi javni kljuc   ", disabled=True, key='-SHOWPU-'),
            sg.Button("   Prikazi privatni kljuc   ", disabled=True, key='-SHOWPR-')
        ],
        [sg.Text(" ")],
        [
            sg.Button(" ▲ Izvezi javni kljuc   ", disabled=True, key='-EXPORTPU-'),
            sg.Button(" ▲ Izvezi privatni kljuc   ", disabled=True, key='-EXPORTPR-'),
            sg.FileBrowse("    ▼ Uvezi kljuc       ", file_types=(("Pem Files", "*.pem"),), key='-IMPORT-', target='-IMPORTINPUT-'),
            sg.Input(key='-IMPORTINPUT-', enable_events=True, visible=False)
        ],
        [
            sg.Button("        Generisi novi par kljuceva        ", button_color=('black', 'green'), key='-KEYGENBUTTON-'),
            sg.Button("                    Obrisi                     ", disabled=True, button_color=('white', 'red'), key='-KEYDELBUTTON-')
        ],
        [
            sg.Table(headings=[' Algoritam ', '     Timestamp     ', '      KeyID      ', '      Ime      ', '          Email          '],
                     values=privateKeyRows, key='-PRTABLE-', row_height=48, enable_events=True,
                     select_mode=sg.TABLE_SELECT_MODE_BROWSE),
            sg.Table(headings=[' Algoritam ', '     Timestamp     ', '      KeyID      ', '      Ime      ', '          Email          ',],
                     values=publicKeyRows, key='-PUTABLE-',
                     visible=False, row_height=48, enable_events=True, select_mode=sg.TABLE_SELECT_MODE_BROWSE)
        ]
    ]
    return sg.Window('Kljucevi', layout, resizable=False)


def openSendWindow():
    global selectedTableSend
    global selectedKeyRowSend
    global privateKeyRows
    global publicKeyRows
    layout = [
        [
            sg.Button("Odaberi privatni kljuc", disabled=True, key='-SENDPRBUTTON-'),
            sg.Button("Odaberi javni kljuc", disabled=True, key='-SENDPUBUTTON-')
        ],
        [
            sg.Table(headings=[' Algoritam ', '     Timestamp     ', '      KeyID      ', '      Ime      ',
                               '          Email          '],
                     values=privateKeyRows, key='-PRTABLE-', row_height=48, enable_events=True,
                     select_mode=sg.TABLE_SELECT_MODE_BROWSE),
            sg.Table(headings=[' Algoritam ', '     Timestamp     ', '      KeyID      ', '      Ime      ',
                               '          Email          ', ],
                     values=publicKeyRows, key='-PUTABLE-',
                     visible=False, row_height=48, enable_events=True, select_mode=sg.TABLE_SELECT_MODE_BROWSE)
        ]
    ]
    return sg.Window('Slanje', layout, resizable=False)


def openReceiveWindow(text):
    charsPerLine = floor(sqrt(len(text)) * 2.5) + 3
    if (charsPerLine < 28): charsPerLine = 28
    layout = [
        [
            sg.Multiline(
                text,
                size=(charsPerLine, (len(text) // charsPerLine) + 2),
                text_color=sg.theme_text_color(),
                background_color=sg.theme_text_element_background_color(),
                disabled=True
            )
        ]
    ]
    return sg.Window('Prijem', layout, resizable=False)


def openGenWindow():
    layout = [
        [
            sg.Text("Algoritam:       "),
            sg.Radio("RSA", "R1", default=True, key='-ALG-'),
            sg.Radio("DSA / ElGamal", "R1", default=False)
        ],
        [
            sg.Text("Velicina kljuca:"),
            sg.Radio("1024", "R2", default=True, key='-LEN-'),
            sg.Radio("2048", "R2", default=False)
        ],
        [
            sg.Text("Ime      "),
            sg.InputText(key='-NAME-')
        ],
        [
            sg.Text("Email   "),
            sg.InputText(key='-EMAIL-')
        ],
        [
            sg.Text("Lozinka"),
            sg.InputText(key='-PASSWORD-')
        ],
        [
            sg.Button("OK", button_color=('black', 'green')),
            sg.Button("CANCEL", button_color=('white', 'red')),
            sg.Text("", text_color='red', key='-LABEL-')
        ]
    ]
    return sg.Window('Novi par kljuceva', layout, resizable=False)

def openCredWindow():
    layout = [
        [
            sg.Text("Ime      "),
            sg.InputText(key='-NAME-')
        ],
        [
            sg.Text("Email   "),
            sg.InputText(key='-EMAIL-')
        ],
        [
            sg.Button("OK", button_color=('black', 'green')),
            sg.Button("CANCEL", button_color=('white', 'red')),
            sg.Text("", text_color='red', key='-LABEL-')
        ]
    ]
    return sg.Window('Unos imena i lozinke', layout, resizable=False)

def openKeyDisplayWindow(key, attributes=None):
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
        ]


    ]
    if (attributes is not None):
        layout.append([sg.Text("============ Parametri Kljuca ============")])
        for key in attributes.keys():
            layout.append([sg.Text(key), sg.Multiline(
                attributes[key],
                size=(charsPerLine-len(key)-3, (len(str(attributes[key])) // charsPerLine) + 2),
                text_color=sg.theme_text_color(),
                background_color=sg.theme_text_element_background_color(),
                disabled=True
            )])

    layout.append([sg.Button("OK", button_color=('black', 'green'))])
    return sg.Window('Kljuc', layout, resizable=False)


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
    return sg.Window("Password", layout, resizable=False)


def openSendMessageWindow():
    layout = [
        [
            sg.Text("Poruka:"), sg.InputText(key='-MESSAGE-')
        ],
        [
            sg.Text("Simetricni algoritam:"),
            sg.Radio("TripleDES", "SYM_ALG", default=True, key='-SYM_ALG-'),
            sg.Radio("AES128", "SYM_ALG", default=False)
        ],
        [
            sg.Button("Posalji", button_color=('black', 'green'), key="-SENDMESSAGE-"),
        ]
    ]
    return sg.Window("Password", layout, resizable=False)
