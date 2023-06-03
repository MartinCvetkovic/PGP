import PySimpleGUI as sg
from math import sqrt, floor

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


def openBaseWindow():
    layout = [
        [sg.Button('Kljucevi')],
        [sg.Button('Posalji poruku')],
        [sg.Button('Primi poruku')]
    ]
    return sg.Window('PGP', layout, resizable=True)


def openKeyWindow():
    global selectedTable
    global privateKeyRows
    global publicKeyRows
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
            sg.Button("Izvezi privatni kljuc", disabled=True, key='-EXPORTPR-'),
            sg.FileBrowse("Uvezi kljuc", file_types=(("Pem Files", "*.pem"),), key='-IMPORT-', target='-IMPORTINPUT-'),
            sg.Input(key='-IMPORTINPUT-', enable_events=True, visible=False)
        ],
        [
            sg.Button("Generisi novi par kljuceva", button_color=('black', 'green'), key='-KEYGENBUTTON-'),
            sg.Button("Obrisi", disabled=True, button_color=('white', 'red'), key='-KEYDELBUTTON-')
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

def openCredWindow():
    layout = [
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
