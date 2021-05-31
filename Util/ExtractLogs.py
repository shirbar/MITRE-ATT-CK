import concurrent.futures
import glob
import os
import threading
from asyncio import Queue
from xml.dom import minidom
from multiprocessing import Pool
import PySimpleGUI as Sx


class ExtractInfo:
    size = 0
    file_count = 0
    count = 0
    total_files = 0
    path = ""


queue = Queue()


# This function extract a set of event ids from the event logs inside the input directory in XML format.
def reset_info():
    ExtractInfo.size = 0
    ExtractInfo.file_count = 0
    ExtractInfo.count = 0
    ExtractInfo.total_files = 0


def extract_event_ids(event_ids, in_path, window):
    reset_info()
    num_worker_threads = 2
    ExtractInfo.path = in_path
    print("retrieving data from = " + str(in_path))
    directory = glob.glob(os.path.join(in_path, '*.xml'))
    ExtractInfo.total_files = len(directory)
    window.FindElement("Files").Update("0/" + str(ExtractInfo.total_files))

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_worker_threads) as executor:
        pool = []
        for filename in directory:
            pool.append(executor.submit(extract_xml, event_ids=event_ids, file_name=filename, window=window))
        #
        for pool in concurrent.futures.as_completed(pool):
            print("thread done")

    print("It's all done")
    if len(event_ids) == 0:
        return False
    return True


def extract_xml(event_ids, file_name, window):
    print("thread starting with file = " + str(file_name))
    logFile = minidom.parse(file_name)
    items = logFile.getElementsByTagName('EventID')
    ExtractInfo.size += len(items)
    window.FindElement("Status").Update("Extracting event ids from " + str(ExtractInfo.path))
    ExtractInfo.file_count += 1
    for x in items:
        ExtractInfo.count += 1
        event_ids.append(int(x.firstChild.data))
        window.FindElement("Percent").Update(str(int((ExtractInfo.count * 100 // ExtractInfo.size) * (
                    ExtractInfo.file_count / ExtractInfo.total_files))) + "%")
    window.FindElement("Files").Update(str(ExtractInfo.file_count) + "/" + str(ExtractInfo.total_files))














"""
def get_size(in_path):
    size = 0
    directory = glob.glob(os.path.join(in_path, '*.xml'))
    print("before 1 calculation size is : " + str(directory))
    for filename in directory:
        print("before 2 calculation size is : " + str(filename))
        logFile = minidom.parse(filename)
        items = logFile.getElementsByTagName('EventID')
        size += len(items)
    print("after calculation size is : " + str(size))
    return size
"""


