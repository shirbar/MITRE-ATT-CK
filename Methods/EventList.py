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
        return EventListHashMap  # invert_hash_map(EventListHashMap)
    except sqlite3.Error as error:
        print("error while connecting to sqlite ", error)


def show_db():
    conn = sqlite3.connect("Databases/EventList.db")
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table';")  # show all the tables in the .db file
    print("mitre_events_table__________________________________________________________________________________")
    print(cur.fetchall())
    cur.execute("SELECT * FROM mitre_events")  # show all the data inside mitre_cti table/
    print(cur.fetchall())
    names = list(map(lambda x: x[0], cur.description))  # show all the columns names
    print(names)
    print("mitre_techniques_table______________________________________________________________________________")
    print(cur.fetchall())
    cur.execute("SELECT * FROM mitre_techniques")  # show all the data inside mitre_cti table/
    print(cur.fetchall())
    names = list(map(lambda x: x[0], cur.description))  # show all the columns names
    print(names)


def invert_hash_map(mitre_hash_map):
    new_dic = {}
    for k, v in mitre_hash_map.items():
        for x in v:
            new_dic.setdefault(str(x), []).append(k)

    return new_dic
