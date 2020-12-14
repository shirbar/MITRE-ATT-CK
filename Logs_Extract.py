import glob
import os
from xml.dom import minidom


# This function extract a set of event ids from windows security event management only files.
def eventId_Extract(pathIn, pathOut):

    print("in dir = " + pathIn)
    print("out dir = " + pathOut)
    eventIdSet = {0}

    for filename in glob.glob(os.path.join(pathIn, '*.xml')):
        mydoc = minidom.parse(filename)
        items = mydoc.getElementsByTagName('EventID')
        for x in items:
            eventIdSet.add(x.firstChild.data)

    eventIdSet.remove(0)
    print(eventIdSet)