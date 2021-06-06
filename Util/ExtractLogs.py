import concurrent.futures
import ctypes
import glob
import os
import threading
from asyncio import Queue
from xml.dom import minidom
from xml.dom.minidom import parseString
from multiprocessing import Pool
import PySimpleGUI as Sx
from lxml import etree
import xml.etree.ElementTree as ElementTree
import re


class ExtractInfo:
    size = 0
    file_count = 0
    count = 0
    total_files = 0


queue = Queue()
executor = None
main_thread = threading.Thread
stop = False


# This function extract a set of event ids from the event logs inside the input directory in XML format.
def reset_info():
    ExtractInfo.size = 0
    ExtractInfo.counter = 0
    ExtractInfo.file_count = 0
    ExtractInfo.total_files = 0
    ExtractInfo.display_file_count = 0


def extract_event_ids(event_ids, in_path, window, num_worker_threads, extract_thread):
    global executor
    global main_thread
    global stop
    stop = False
    main_thread = extract_thread
    reset_info()
    print("retrieving data from = " + str(in_path))
    directory = glob.glob(os.path.join(in_path, '*.xml'))
    ExtractInfo.total_files = len(directory)
    window.FindElement("Files").Update("0/" + str(ExtractInfo.total_files))

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=num_worker_threads)
    pool = []
    for filename in directory:
        pool.append(executor.submit(extract_xml, event_ids=event_ids, file_name=filename, window=window))
    for pool in concurrent.futures.as_completed(pool):
        pass
    executor = None
    if len(event_ids) == 0:
        return False
    return True


def extract_xml(event_ids, file_name, window):
    global stop
    if stop:
        return
    print("thread starting with file = " + str(file_name))
    tree = ElementTree.parse(file_name)
    xml_str = str(ElementTree.tostring(tree.getroot(), encoding='utf8', method='xml'))
    result = re.findall('<ns0:EventID>(.[0-9]*)</ns0:EventID>', xml_str)
    window.FindElement("Status").Update("\t\tExtracting Event IDs...")
    ExtractInfo.file_count += 1
    ExtractInfo.size += len(result)
    for r in result:
        ExtractInfo.counter += 1
        window.FindElement("Percent").Update(str(int((ExtractInfo.counter * 100 // ExtractInfo.size) * (
                ExtractInfo.file_count / ExtractInfo.total_files))) + "%")
        if int(r) not in event_ids:
            event_ids.append(int(r))
    ExtractInfo.display_file_count += 1
    window.FindElement("Files").Update(str(ExtractInfo.display_file_count) + "/" + str(ExtractInfo.total_files))


def terminate_threads():
    global executor
    global stop
    stop = True
    if executor is None:
        return
    stop = True
    terminate_thread(main_thread)
    for t in executor._threads:
        terminate_thread(t)


def terminate_thread(thread):
    if not thread.is_alive():
        return
    exc = ctypes.py_object(SystemExit)
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(
        ctypes.c_long(thread.ident), exc)
    if res == 0:
        raise ValueError("nonexistent thread id")
    elif res > 1:
        ctypes.pythonapi.PyThreadState_SetAsyncExc(thread.ident, None)
        raise SystemError("PyThreadState_SetAsyncExc failed")


"""
    logFile = minidom.parse(file_name)
    items = logFile.getElementsByTagName('EventID')
    print("the items are: ")
    ExtractInfo.size += len(items)
    window.FindElement("Status").Update("\t\tExtracting Event IDs...")
    ExtractInfo.file_count += 1
    for x in items:
        ExtractInfo.count += 1
        event_ids.append(int(x.firstChild.data))
        window.FindElement("Percent").Update(str(int((ExtractInfo.count * 100 // ExtractInfo.size) * (
                    ExtractInfo.file_count / ExtractInfo.total_files))) + "%")
    window.FindElement("Files").Update(str(ExtractInfo.file_count) + "/" + str(ExtractInfo.total_files))
"""














