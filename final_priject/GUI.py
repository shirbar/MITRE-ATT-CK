import PySimpleGUI as sg

from Logs_Extract import eventId_Extract
from Mtre_Api_json import getMitreDataFromUrl

dirIn_list = [
    [
        sg.Text("Enter input directory:  "),
        sg.In(size=(25, 1), enable_events=True, key="-FOLDER-IN-"),
        sg.FolderBrowse(),
    ],

]

dirOut_list = [
    [
        sg.Text("Enter output directory:"),
        sg.In(size=(25, 1), enable_events=True, key='-FOLDER-OUT-'),
        sg.FolderBrowse(),
    ],
]

butn_list = [
    [
        sg.Button("OK"),
        sg.Exit()
    ]
]
# check box layout
checkBox_Malware_Archeology = [
    [
        sg.Checkbox('Malware Archeology')
    ]
]

checkBox_miriam = [
    [
        sg.Checkbox('Miriam')
    ]
]

checkBox_mitre_cti = [
    [
        sg.Checkbox('MITRE/cti', key='mitre/cti')
    ]
]

checkBox_list = [
    [sg.Column(checkBox_miriam)],
    [sg.Column(checkBox_mitre_cti)],
    [sg.Column(checkBox_Malware_Archeology)]
]

layout = [

        [sg.Column(dirIn_list)],
        #sg.VSeperator(),
        [sg.Column(dirOut_list)],
        [sg.Column(checkBox_list)],
        [sg.Column(butn_list)],

]

window = sg.Window("First Demo", layout)

while True:
    event, values = window.read()
    # End program if user closes window or
    # presses the OK button
    if event in (None, 'Exit'):
        break
    if event == 'OK':
        if window.FindElement('mitre/cti').Get():
            eventId_Extract(values['-FOLDER-IN-'], values['-FOLDER-OUT-'])
            getMitreDataFromUrl()
            print("pressed OK")

window.close()