import urllib.request
import sqlite3
import os.path


def update_event_list_db():
    url = "https://raw.githubusercontent.com/miriamxyra/EventList/master/EventList/internal/data/EventList.db"
    urllib.request.urlretrieve(url, 'EventList.db')


def get_event_list_hash_map():
    EventListHashMap = {}
    if not os.path.exists("EventList.db"):
        update_event_list_db()
    try:
        sqliteConnection = sqlite3.connect("EventList.db")
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
