import glob
import os
from xml.dom import minidom
from multiprocessing import Pool
import PySimpleGUI as Sx


# This function extract a set of event ids from the event logs inside the input directory in XML format.
def extract_event_ids(event_ids, in_path, window):
    print("retrieving data from = " + str(in_path))
    directory = glob.glob(os.path.join(in_path, '*.xml'))
    total_files = len(directory)
    file_count = 0
    for filename in directory:
        file_count += 1
        window.FindElement("Files").Update(str(file_count) + "/" + str(total_files))
        window.FindElement("Percent").Update("0%")
        logFile = minidom.parse(filename)
        items = logFile.getElementsByTagName('EventID')
        size = len(items)
        count = 0
        for x in items:
            count += 1
            event_ids.append(int(x.firstChild.data))
            window.FindElement("Percent").Update(str(count * 100 // size) + "%")
    if len(event_ids) == 0:
        return False
    return True
