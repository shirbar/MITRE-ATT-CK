from time import sleep
import PySimpleGUI as Sg

from Util.ExtractLogs import extract_event_ids
from Util.MergeHashMaps import merge_hash_maps
from Util.GetTTPs import get_ttp_from_event_ids
from Methods.MITRECti import get_mitre_cti_hash_map
import Methods.EventList as EventList

Sg.theme('DarkBlue13')

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


def threaded_function(user_event_ids):
    #print("starting thread --------------")
    extract_event_ids(user_event_ids, values['-FOLDER-IN-'])
    #TODO change a global value to let the reload bar know that we are done
    #print("finished ---------")


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
                pass
            if checkBoxes[1]:
                merge_hash_maps(mainHashMap, EventList.get_event_list_hash_map())
            if checkBoxes[2]:
                pass
                # TODO add getMalwareArchaeologyHashMap()
                # merge_hash_maps(mainHashMap, getMalwareArchaeologyHashMap())

            # Running the user event ids on the hash map he selected.
            # Those prints are only for testing
            print("The hash map selected by the user check boxes:")
            print(mainHashMap)
            # extracting the event ids from the files inside the folder
            user_event_ids = []
            successfully_extracted = True
            thread = Sg.Thread(target=threaded_function, args=(user_event_ids,))
            thread.start()
            # TODO search if I can get the length of the XML objects

            for i in range(1, 300):
                Sg.one_line_progress_meter("Progress bar", i+1, 300, "key", "retrieving data from " + str(values['-FOLDER-IN-']))
            thread.join()
            if successfully_extracted:
                user_event_ids = set(user_event_ids)
                # Sg.popup_quick_message("extracting event ids...")
                print("\nThe user event ids:")
                print(user_event_ids)
                TTPs = get_ttp_from_event_ids(mainHashMap, user_event_ids)
                print("\nThe end result TTPs:")
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
        Sg.popup_ok("Event List DB has updated.", title="Done", auto_close_duration=5)
    elif event == "Update MalwareArcheology DB":
        Sg.popup_ok("TODO - update me")

window.close()
