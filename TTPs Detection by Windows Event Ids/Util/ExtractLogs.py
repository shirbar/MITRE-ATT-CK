import glob
import os
from xml.dom import minidom
import PySimpleGUI as Sx


# This function extract a set of event ids from the event logs inside the input directory in XML format.
def extract_event_ids(event_ids, in_path):
    print("retrieving data from = " + str(in_path))
    for filename in glob.glob(os.path.join(in_path, '*.xml')):
        Sx.popup_animated("a/loading_img.gif")
        logFile = minidom.parse(filename)
        items = logFile.getElementsByTagName('EventID')
        for x in items:
            event_ids.append(int(x.firstChild.data))
    Sx.popup_animated(None)
    if len(event_ids) == 0:
        return False
    return True
