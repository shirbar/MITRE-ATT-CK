import unittest
import os
import sys
import time
import sqlite3
import json
import urllib.request
from urllib.request import urlopen
import re


class MyTestCase(unittest.TestCase):
    def test_event_list_update_duration(self):
        t0 = time.time()
        url = "https://raw.githubusercontent.com/miriamxyra/EventList/master/EventList/internal/data/EventList.db"
        fileName, headers = urllib.request.urlretrieve(url, '../Databases/EventList.db')
        with open("../Util/MethodsDate.json", "r") as jsonFile:
            data = json.load(jsonFile)
        data["EventList"] = headers['Content-Length']
        with open("../Util/MethodsDate.json", "w") as jsonFile:
            json.dump(data, jsonFile)
        t1 = time.time()
        duration = t1 - t0
        print("Event List Update Duration: " + str(duration))
        self.assertTrue(True)

    def test_mitre_cti_update_duration(self):
        def get_event_ids(description):
            event_ids = re.findall(r'\b\d+\b', description)
            for event in reversed(event_ids):
                if int(event) < 1100 or 1108 < int(event) < 4608:
                    event_ids.remove(event)
            event_ids = set(event_ids)
            return event_ids

        def invert_mitre_hash_map(mitre_hash_map):
            new_dic = {}
            for k, v in mitre_hash_map.items():
                for x in v:
                    new_dic.setdefault(int(x), []).append(k)

            return new_dic

        t0 = time.time()

        conn = sqlite3.connect("../Databases/Mitre_CTI.db")
        cur = conn.cursor()
        create = "CREATE TABLE IF NOT EXISTS mitre_cti( event_id INT, ttp TEXT);"
        cur.execute(create)  # execute SQL commands
        conn.commit()

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

        mitre_cti_data = invert_mitre_hash_map(mitre_hash_technique)
        mitre_cti_data = [(int(i), str(mitre_cti_data[i])) for i in mitre_cti_data]
        insert_command = "INSERT INTO mitre_cti VALUES(?,?);"

        cur.executemany(insert_command, mitre_cti_data)
        conn.commit()

        t1 = time.time()
        duration = t1 - t0
        print("Mitre Cti Update Duration: " + str(duration))
        self.assertTrue(True)


if __name__ == '__main__':
    unittest.main()
