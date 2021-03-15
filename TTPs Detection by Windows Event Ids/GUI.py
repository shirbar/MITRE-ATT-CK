import json
from time import sleep
import PySimpleGUI as Sg
import urllib.request
from datetime import datetime


from Util.ExtractLogs import extract_event_ids
from Util.MergeHashMaps import merge_hash_maps
from Util.GetTTPs import get_ttp_from_event_ids
from Methods.MITRECti import get_mitre_cti_hash_map
import Methods.EventList as EventList

Sg.theme('DarkBlue13')

dirIn_list = [
    [
        Sg.Text("Enter the input directory:\t"),
        Sg.In(size=(40, 1), enable_events=True, key="-FOLDER-IN-"),
        Sg.FolderBrowse(),
    ],

]

dirOut_list = [
    [
        Sg.Text("Enter the output directory:\t"),
        Sg.In(size=(40, 1), enable_events=True, key='-FOLDER-OUT-'),
        Sg.FolderBrowse(),
    ],
]

button_list = [
    [
        Sg.Button("SCAN"),
        Sg.Exit(),
    ]
]
# check box layout

MITRE_cti_checkBox = [
    [
        Sg.Checkbox('MITRE/cti\t\t', key='MITRE/ctiCB'),
        Sg.Button("Update MITRE/cti DB", key='MITRE_CTI_Update_Button', size=(25, 1)),
        Sg.Text("Checking for update...", key="MITRE/CTI", size=(15, 1))
    ]
]

EventList_checkBox = [
    [
        Sg.Checkbox('EventList by Miriam Wiesner\t', key='EventListCB'),
        Sg.Button("Update EventList DB", key='EventList_Update_Button', size=(25, 1)),
        Sg.Text("Checking for update...", key="EventList", size=(15, 1))
    ]
]

Malware_Archeology_checkBox = [
    [
        Sg.Checkbox('Malware Archeology\t', key='MalwareArcheologyCB'),
        Sg.Button("Update MalwareArcheology DB", key='MalwareArcheology_Update_Button', size=(25, 1)),
        Sg.Text("Checking for update...", key="Malware", size=(15, 1))
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

methodUrls = ["https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json", "https://raw.githubusercontent.com/miriamxyra/EventList/master/EventList/internal/data/EventList.db", "https://raw.githubusercontent.com/miriamxyra/EventList/master/EventList/internal/data/EventList.db"]
original_files = ["MITRE/CTI", "EventList", "Malware"]


def check_connection():
    try:
        urllib.request.urlopen('https://www.google.com/', timeout=2)
        return True
    except:
        return False


def disable_buttons():
    global window
    window.FindElement('MITRE_CTI_Update_Button').Update(disabled=True)
    window.FindElement('EventList_Update_Button').Update(disabled=True)
    window.FindElement('MalwareArcheology_Update_Button').Update(disabled=True)
    window.Refresh()


def enable_button(j):
    global window
    if j == 0:
        window.FindElement('MITRE_CTI_Update_Button').Update(disabled=False)
    elif j == 1:
        window.FindElement('EventList_Update_Button').Update(disabled=False)
    else:
        window.FindElement('MalwareArcheology_Update_Button').Update(disabled=False)


def threaded_function(user_ids):
    # print("starting thread --------------")
    extract_event_ids(user_ids, values['-FOLDER-IN-'])
    # TODO change a global value to let the reload bar know that we are done
    # print("finished ---------")


def update_checker():
    try:
        urllib.request.urlopen('https://www.google.com/', timeout=2)
        with open("Util/MethodsDate.json") as json_file:
            methodsSize = json.load(json_file)
            for j in range(0, 3):
                fileName, headers = urllib.request.urlretrieve(methodUrls[j])
                if methodsSize[original_files[j]] != headers['Content-Length']:
                    enable_button(j)
                    window.FindElement(original_files[j]).Update("Expired")
                else:
                    window.FindElement(original_files[j]).Update(datetime.now().strftime("%d/%m/%y"))
    except:
        for j in range(0, 3):
            window.FindElement(original_files[j]).Update("Offline")


window = Sg.Window("TTP Detection", layout).Finalize()

disable_buttons()

thread = Sg.Thread(target=update_checker)
thread.start()

while True:
    event, values = window.read()
    # End program if user closes the window or
    if event in (None, 'Exit'):
        break
    if event == 'SCAN':
        # checking if any of the check boxes are checked.
        checkBoxes = [False] * 3
        if window.FindElement('MITRE/ctiCB').Get():
            checkBoxes[0] = True
        if window.FindElement('EventListCB').Get():
            checkBoxes[1] = True
        if window.FindElement('MalwareArcheologyCB').Get():
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
                Sg.one_line_progress_meter("Progress bar", i + 1, 300, "key",
                                           "retrieving data from " + str(values['-FOLDER-IN-']))
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
    elif event == 'MITRE_CTI_Update_Button':
        Sg.popup_ok("TODO - update me")
    elif event == 'EventList_Update_Button':
        EventList.update_event_list_db()
        window.FindElement('EventList_Update_Button').Update(disabled=True)
        Sg.popup_ok("    Event List DB has updated.    ", title="Done")
    elif event == 'MalwareArcheology_Update_Button':
        Sg.popup_ok("TODO - update me")

window.close()
