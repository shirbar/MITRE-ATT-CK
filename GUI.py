import ctypes
import os
import shutil
import time

import PySimpleGUI as Sg
import urllib.request
import threading
from datetime import datetime

from Util.ExtractLogs import extract_event_ids
from Util.MergeHashMaps import merge_hash_maps
from Util.GetTTPs import get_ttp_from_event_ids
import Methods.EventList as EventList
import Methods.MITRECti as MITRECti
import Methods.Malware as Malware
from Output import createOutputAsMatrix

Sg.theme('DarkBlue13')
MAX_THREADS = os.cpu_count()*5


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

thread_list = [
    [
        Sg.Text("Number of Threads:\t"),
        Sg.In(size=(3, 1), enable_events=True, key='treads_key', default_text="2"),
        Sg.Text("/  " + str(MAX_THREADS)),
        Sg.Button("Max", key='max_threads'),
    ],
]

button_list = [
    [
        Sg.Button("SCAN", key='Scan_Button'),
        Sg.Exit(),
        Sg.Text("\t\t", key="Status", size=(45, 1), text_color='yellow'),
        Sg.Text("", key="Files", size=(4, 1), text_color='yellow'),
        Sg.Text("", key="Percent", size=(4, 1), text_color='yellow'),
    ]
]
# check box layout

EventList_checkBox = [
    [
        Sg.Checkbox('EventList by Miriam Wiesner\t', key='EventListCB'),
        Sg.Button("Update EventList DB", key='EventList_Update_Button', size=(25, 1)),
        Sg.Text("", key="EventList", size=(15, 1), text_color='yellow')
    ]
]

Malware_Archeology_checkBox = [
    [
        Sg.Checkbox('Malware Archeology\t', key='MalwareArcheologyCB'),
        Sg.Button("Update MalwareArcheology DB", key='MalwareArcheology_Update_Button', size=(25, 1)),
        Sg.Text("", key="Malware", size=(15, 1), text_color='yellow')
    ]
]

MITRE_cti_checkBox = [
    [
        Sg.Checkbox('MITRE/cti\t\t', key='MITRE/ctiCB'),
        Sg.Button("Update MITRE/cti DB", key='MITRE_CTI_Update_Button', size=(25, 1)),
        Sg.Text("", key="MITRE/CTI", size=(15, 1), text_color='yellow')
    ]
]

checkBox_list = [
    [Sg.Column(EventList_checkBox)],
    [Sg.Column(Malware_Archeology_checkBox)],
    [Sg.Column(MITRE_cti_checkBox)]
]

layout = [
    [Sg.Column(dirIn_list)],
    [Sg.Column(dirOut_list)],
    [Sg.Column(thread_list)],
    [Sg.Column(checkBox_list)],
    [Sg.Column(button_list)],
]

original_files = ["EventList", "Malware", "MITRE/CTI"]


# This function check if there is a internet connection
def check_connection():
    try:
        urllib.request.urlopen('https://www.google.com/', timeout=2)
        return True
    except Exception as e:
        print(e)
        return False


# This function disable the update buttons if there no update available.
# method values: (0: EventList, 1: Malware Archeology, 2: MITRE/CTI, 3: all of the methods)
def disable_buttons(method):
    global window
    if method == 0:
        window.FindElement('EventList_Update_Button').Update(disabled=True)
    elif method == 1:
        window.FindElement('MalwareArcheology_Update_Button').Update(disabled=True)
    elif method == 2:
        window.FindElement('MITRE_CTI_Update_Button').Update(disabled=True)
    else:
        window.FindElement('EventList_Update_Button').Update(disabled=True)
        window.FindElement('MalwareArcheology_Update_Button').Update(disabled=True)
        window.FindElement('MITRE_CTI_Update_Button').Update(disabled=True)
    window.Refresh()


# This function enable the update buttons if there is a update available.
def enable_button(j):
    global window
    if j == 0:
        window.FindElement('EventList_Update_Button').Update(disabled=False)
    elif j == 1:
        window.FindElement('MalwareArcheology_Update_Button').Update(disabled=False)
    else:
        window.FindElement('MITRE_CTI_Update_Button').Update(disabled=False)


# This function is a threaded function to extract event ids fro, the .xml file
def extract_event_thread(user_ids):
    global window
    start_time = time.time()
    window.FindElement("Status").Update("\t\tParsing the XML files...")
    window.FindElement("Files").Update("0/0")
    window.FindElement("Percent").Update("0%")
    thread_number = int(values['treads_key']) if (0 < int(values['treads_key']) < MAX_THREADS) else 2
    print(thread_number)
    extract_event_ids(user_ids, values['-FOLDER-IN-'], window, thread_number)
    user_ids = set(user_ids)
    print("\nThe user event ids:")
    print(user_ids)
    TTPs = get_ttp_from_event_ids(mainHashMap, user_ids)
    print("\nThe end result TTPs:")
    print(convert_output(TTPs))
    result_time = (time.time() - start_time)
    window.FindElement("Status").Update("\t\tFinished in " + str("{:.2f}".format(result_time)) + " seconds.")
    window.FindElement('Scan_Button').Update(disabled=False)
    window.Refresh()
    createOutputAsMatrix(convert_output(TTPs))
    if values['-FOLDER-OUT-'] != "":
        copy_file_to_out_dir(values['-FOLDER-OUT-'])


# copy the output file to the output dir
def copy_file_to_out_dir(out_dir):
    cwd = os.getcwd()
    original = r'' + cwd + '\\Mapping_Res_to_MitreAttack.xlsx'
    target = r''+out_dir + '/Mapping_Res_to_MitreAttack.xlsx'
    shutil.copyfile(original, target)


# This function check if there is an update
def update_checker():
    try:
        if urllib.request.urlopen('https://www.google.com/', timeout=2):
            for j in range(0, 3):
                window.FindElement(original_files[j]).Update("Checking for update...")
                if check_for_update(j):
                    enable_button(j)
                    window.FindElement(original_files[j]).Update("Expired", text_color='red')
                else:
                    window.FindElement(original_files[j]).Update("Up to Date: " + str(datetime.now().strftime("%d/%m/%y")), text_color="white")
        else:
            Sg.popup_notify("No internet Connection, Couldn't check for updates.", title="Warning")
    except Exception as e:
        print(e)
        for j in range(0, 3):
            window.FindElement(original_files[j]).Update("Update Error")


# method values: (0: EventList, 1: Malware Archeology, 2: MITRE/CTI)
def check_for_update(method):
    if method == 0:
        return EventList.check_for_update()
    elif method == 1:
        return Malware.check_for_update()
    else:
        return MITRECti.check_for_update()


def update_event_list_db():
    EventList.update_event_list_db()
    window.FindElement(original_files[0]).Update(
        "Up to Date: " + str(datetime.now().strftime("%d/%m/%y")), text_color="white")


def update_malware_db():
    Malware.get_malware_hash_map()
    window.FindElement(original_files[1]).Update(
        "Up to Date: " + str(datetime.now().strftime("%d/%m/%y")), text_color="white")


def update_mitre_cti_db():
    MITRECti.save_mitre_cti_to_db()
    window.FindElement(original_files[2]).Update(
        "Up to Date: " + str(datetime.now().strftime("%d/%m/%y")), text_color="white")


window = Sg.Window("TTP Detection", layout).Finalize()
extract_thread = threading.Thread()

disable_buttons(3)
check_update_thread = threading.Thread(target=update_checker)
check_update_thread.start()


#############################################################################################################################
# change the end result form
def convert_output(list_):
    newList = []

    for item in list_:
        if len(item) > 1 and item[0] != 'T':
            item = item.split("'")
            for x in item:
                if ("[" not in x) and ("]" not in x) and ("'" not in x) and ("," not in x):
                    newList.append(x)
        else:
            newList.append(item)
    return set(newList)


# This function terminate threads
def terminate_thread(thread):
    global stopped
    if not thread.is_alive():
        return
    exc = ctypes.py_object(SystemExit)
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(
        ctypes.c_long(thread.ident), exc)
    stopped = True
    if res == 0:
        raise ValueError("nonexistent thread id")
    elif res > 1:
        ctypes.pythonapi.PyThreadState_SetAsyncExc(thread.ident, None)
        raise SystemError("PyThreadState_SetAsyncExc failed")


# main loop
while True:
    event, values = window.read()
    stopped = False
    # End program if user closes the window or
    if event in (None, 'Exit'):
        terminate_thread(check_update_thread)
        break
    if event == 'Scan_Button':
        # checking if any of the check boxes are checked.
        checkBoxes = [False] * 3
        if window.FindElement('EventListCB').Get():
            checkBoxes[0] = True
        if window.FindElement('MalwareArcheologyCB').Get():
            checkBoxes[1] = True
        if window.FindElement('MITRE/ctiCB').Get():
            checkBoxes[2] = True
        # making sure that at least one check box is checked.
        if values['-FOLDER-IN-'] == "":
            Sg.popup_ok("Input Error", "Please browse and specify the directory of the windows logs.")
        elif True in checkBoxes:
            # creating a hash map based on the selection of the user
            mainHashMap = {}
            if checkBoxes[0]:
                merge_hash_maps(mainHashMap, EventList.get_event_list_hash_map())
            if checkBoxes[1]:
                merge_hash_maps(mainHashMap, Malware.get_malware_archaeology_hashmap_from_db())     # TODO merge_hash_maps(mainHashMap, getMalwareArchaeologyHashMap())
            if checkBoxes[2]:
                merge_hash_maps(mainHashMap, MITRECti.get_mitre_cti_hash_map_from_db())

            # Running the user event ids on the hash map he selected.
            # Those prints are only for testing
            print("The hash map selected by the user check boxes:")
            print(mainHashMap)

            # extracting the event ids from the files inside the folder
            window.FindElement('Scan_Button').Update(disabled=True)
            user_event_ids = []
            extract_thread = threading.Thread(target=extract_event_thread, args=(user_event_ids,))
            extract_thread.start()

            """
            for i in range(1, size + 1):
                progress_event = Sg.one_line_progress_meter("Progress bar", i, size, "key",
                                                            "retrieving data from " + str(values['-FOLDER-IN-']))
                if progress_event is False:
                    terminate_thread(extract_thread)
                    break

            output_thread = threading.Thread(target=output_result, args=)
            extract_thread.join()
            if not stopped:
                user_event_ids = set(user_event_ids)
                # Sg.popup_quick_message("extracting event ids...")
                print("\nThe user event ids:")
                print(user_event_ids)
                TTPs = get_ttp_from_event_ids(mainHashMap, user_event_ids)
                print("\nThe end result TTPs:")
                print(convert_output(TTPs)) ######
                createOutputAsMatrix(convert_output(TTPs))
            # else: Sg.popup_ok("Input Error", "The selected directory does not contain XML log file.")
            """
        else:
            Sg.popup_ok("Selection Error", "please select at least one check box method.")

        # resetting the check boxes to False.
        checkBoxes = False * 3

    elif event == 'EventList_Update_Button':
        event_thread = threading.Thread(target=update_event_list_db)
        event_thread.start()
        window.FindElement(original_files[0]).Update("Updating...", text_color='yellow')
        disable_buttons(0)

    elif event == 'MalwareArcheology_Update_Button':
        malware_thread = threading.Thread(target=update_malware_db)
        malware_thread.start()
        window.FindElement(original_files[1]).Update("Updating...", text_color='yellow')
        disable_buttons(1)

    elif event == 'MITRE_CTI_Update_Button':
        mitre_thread = threading.Thread(target=update_mitre_cti_db)
        mitre_thread.start()
        window.FindElement(original_files[2]).Update("Updating...", text_color='yellow')
        disable_buttons(2)
    elif event == 'max_threads':
        window.FindElement("treads_key").Update(str(MAX_THREADS))

window.close()
