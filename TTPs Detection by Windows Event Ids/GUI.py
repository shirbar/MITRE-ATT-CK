import PySimpleGUI as Sg

from Util.ExtractLogs import extract_event_ids
from Util.MergeHashMaps import merge_hash_maps
from Util.GetTTPs import get_ttp_from_event_ids
from Methods.MITRECti import get_mitre_cti_hash_map
import Methods.EventList as EventList

Sg.theme('BlueMono')

dirIn_list = [
    [
        Sg.Text("Enter the input directory:\t"),
        Sg.In(size=(25, 1), enable_events=True, key="-FOLDER-IN-"),
        Sg.FolderBrowse(),
    ],

]

dirOut_list = [
    [
        Sg.Text("Enter the output directory:\t"),
        Sg.In(size=(25, 1), enable_events=True, key='-FOLDER-OUT-'),
        Sg.FolderBrowse(),
    ],
]

button_list = [
    [
        Sg.Button("SCAN"),
        Sg.Exit()
    ]
]
# check box layout

MITRE_cti_checkBox = [
    [
        Sg.Checkbox('MITRE/cti\t\t', key='MITRE/cti'),
        Sg.Button("Update MITRE/cti DB")
    ]
]

EventList_checkBox = [
    [
        Sg.Checkbox('EventList by Miriam Wiesner\t', key='EventListDB'),
        Sg.Button("Update EventList DB")
    ]
]

Malware_Archeology_checkBox = [
    [
        Sg.Checkbox('Malware Archeology\t', key='MalwareArcheology'),
        Sg.Button("Update MalwareArcheology DB")
    ]
]

checkBox_list = [
    [Sg.Column(MITRE_cti_checkBox)],
    [Sg.Column(EventList_checkBox)],
    [Sg.Column(Malware_Archeology_checkBox)]
]

layout = [
        [Sg.Column(dirIn_list)],
        [Sg.Column(dirOut_list)],
        [Sg.Column(checkBox_list)],
        [Sg.Column(button_list)],
]

window = Sg.Window("TTP Detection", layout)

while True:
    event, values = window.read()
    # End program if user closes the window or
    # click on the SCAN button
    if event in (None, 'Exit'):
        break
    if event == 'SCAN':
        # checking if any of the check boxes are checked.
        checkBoxes = [False] * 3
        if window.FindElement('MITRE/cti').Get():
            checkBoxes[0] = True
        if window.FindElement('EventListDB').Get():
            checkBoxes[1] = True
        if window.FindElement('MalwareArcheology').Get():
            checkBoxes[2] = True
        # making sure that at least one check box is checked.
        if values['-FOLDER-IN-'] == "":
            Sg.popup_ok("Input Error", "Please browse and specify the directory of the windows logs.")
        elif True in checkBoxes:
            # creating a hash map based on the selection of the user
            mainHashMap = {}
            if checkBoxes[0]:
                merge_hash_maps(mainHashMap, get_mitre_cti_hash_map())
            if checkBoxes[1]:
                merge_hash_maps(mainHashMap, EventList.get_event_list_hash_map())
            if checkBoxes[2]:
                pass
                # TODO add getMalwareArchaeologyHashMap()
                # merge_hash_maps(mainHashMap, getMalwareArchaeologyHashMap())

            # Running the user event ids on the hash map he selected.
            # Those prints are only for testing
            print("the main hash map selected by the user output:")
            print(mainHashMap)
            # extracting the event ids from the files inside the folder
            userEventIds = []
            if extract_event_ids(userEventIds, values['-FOLDER-IN-']):
                userEventIds = set(userEventIds)
                # Sg.popup_quick_message("extracting event ids...")
                print("printing the user event ids")
                print(userEventIds)

                TTPs = get_ttp_from_event_ids(mainHashMap, userEventIds)
                print("printing the TTPs")
                print(TTPs)
            else:
                Sg.popup_ok("Input Error", "The selected directory does not contain XML log file.")

        else:
            Sg.popup_ok("Selection Error", "please select at least one check box method.")

        # resetting the check boxes to False.
        checkBoxes = False * 3
    elif event == "Update MITRE/cti DB":
        Sg.popup_ok("TODO - update me")
    elif event == "Update EventList DB":
        EventList.update_event_list_db()
        Sg.popup_ok("Updating Event List DB completed.", title="Done", auto_close_duration=5)
    elif event == "Update MalwareArcheology DB":
        Sg.popup_ok("TODO - update me")


window.close()
