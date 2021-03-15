import json
import urllib.request
import sqlite3
import os.path


def update_event_list_db():
    url = "https://raw.githubusercontent.com/miriamxyra/EventList/master/EventList/internal/data/EventList.db"
    fileName, headers = urllib.request.urlretrieve(url, 'Databases/EventList.db')
    with open("Util/MethodsDate.json", "r") as jsonFile:
        data = json.load(jsonFile)
    data["EventList"] = headers['Content-Length']
    with open("Util/MethodsDate.json", "w") as jsonFile:
        json.dump(data, jsonFile)


def get_event_list_hash_map():
    EventListHashMap = {}
    if not os.path.exists("Databases/EventList.db"):
        update_event_list_db()
    try:
        sqliteConnection = sqlite3.connect("Databases/EventList.db")
        cursor = sqliteConnection.cursor()
        sqlite_select_Query = "select E.event_id, T.technique_id from mitre_events E, mitre_techniques T where " \
                              "E.technique_id = T.id; "
        cursor.execute(sqlite_select_Query)
        record = cursor.fetchall()
        for rec in record:
            if rec[0] in EventListHashMap.keys():
                EventListHashMap[rec[0]].append(rec[1])
            else:
                EventListHashMap[rec[0]] = [rec[1]]
        cursor.close()
        sqliteConnection.close()
        return EventListHashMap
    except sqlite3.Error as error:
        print("error while connecting to sqlite ", error)
