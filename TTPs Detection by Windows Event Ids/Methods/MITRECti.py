import json
import urllib.request
from urllib.request import urlopen
import re
import sqlite3


# This function pull mitre json and send to local DB the new hash map
def get_mitre_cti_hash_map():
    mitre_hash_technique = {}
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    json_url = urlopen(url)
    data = json.loads(json_url.read())

    for i in data['objects']:
        if 'x_mitre_data_sources' in i:
            if 'Windows event logs' in i['x_mitre_data_sources']:
                if 'Event ID' in i['x_mitre_detection']:
                    eventIds = get_event_ids(i['x_mitre_detection'])
                    key = i['external_references'][0]['external_id']
                    if key in mitre_hash_technique.keys():
                        mitre_hash_technique[key].append(eventIds)
                    else:
                        mitre_hash_technique[key] = eventIds
    return invert_mitre_hash_map(mitre_hash_technique)


# This function gets the x_mire_detection str.split string and return the event ids thet can be use with this techniqe
def get_event_ids(description):
    eventIds = re.findall(r'\b\d+\b', description)
    for event in reversed(eventIds):
        if int(event) < 1100 or 1108 < int(event) < 4608:
            eventIds.remove(event)
    eventIds = set(eventIds)
    return eventIds


def invert_mitre_hash_map(mitre_hash_map):
    new_dic = {}
    for k, v in mitre_hash_map.items():
        for x in v:
            new_dic.setdefault(int(x), []).append(k)

    return new_dic


# This function download the json file from mitre cti API and save it.
def update_mitre_cti_db():
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    urllib.request.urlretrieve(url, 'Original Files/attack.json')
    return save_to_db()


# This function save the mitre cti tuple to Mitre_CTI.db file
def save_to_db():
    conn = sqlite3.connect("../Databases/Mitre_CTI.db")
    cur = conn.cursor()
    create = "CREATE TABLE IF NOT EXISTS mitre_cti( ttp TEXT, event_ids TEXT)";

    cur.execute(create)  # execute SQL commands
    conn.commit()

    mitre_cti_data = get_mitre_cti_hash_map()

    mitre_cti_data = [(i, str(mitre_cti_data[i])) for i in mitre_cti_data]

    insert_command = "INSERT INTO mitre_cti VALUES(?,?);"

    cur.executemany(insert_command, mitre_cti_data)
    conn.commit()
    show_db()


# this function shwos the data inside Mitre_CTI.db
def show_db():
    conn = sqlite3.connect("../Databases/Mitre_CTI.db")
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table';")  # show all the tables in the .db file
    print("Mitre_CTI.db__________________________________________________________________________________")
    print(cur.fetchall())
    cur.execute("SELECT * FROM mitre_cti")  # show all the data inside mitre_cti table/
    print(cur.fetchall())
    names = list(map(lambda x: x[0], cur.description))  # show all the columns names
    print(names)
    print("Mitre_CTI.db_end______________________________________________________________________________")


# update_mitre_cti_db
#save_to_db()

#show_db()
