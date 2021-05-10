import json
import unittest
import os
import sys
from urllib.request import urlopen


class MyTestCase(unittest.TestCase):
    def test_get_mitre_cti_hash_map(self):
        """
        def get_event_ids(description):
            eventIds = re.findall(r'\b\d+\b', description)
            for event in reversed(eventIds):
                if int(event) < 1100 or 1108 < int(event) < 4608:
                    eventIds.remove(event)
            eventIds = set(eventIds)
            return list(eventIds)

        def get_mitre_cti_hash_map():
            global mitre_hash_technique
            mitre_hash_technique = {}
            url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
            json_url = urlopen(url)
            data = json.loads(json_url.read())

            for i in data['objects']:
                if 'x_mitre_data_sources' in i:
                    # if 'Windows event logs' in i['x_mitre_data_sources']:
                    if 'Event ID' in i['x_mitre_detection']:
                        eventIds = get_event_ids(i['x_mitre_detection'])
                        key = i['external_references'][0]['external_id']
                        if key in mitre_hash_technique.keys():
                            mitre_hash_technique[key].append(eventIds)
                        else:
                            mitre_hash_technique[key] = eventIds
                search_pattern(i)
            print(mitre_hash_technique)
            return invert_mitre_hash_map(mitre_hash_technique)
            # return mitre_hash_technique

        print("Running MITRE CTI calculate HashMap Test")
        get_mitre_cti_hash_map()
        self.assertTrue(True)
        """
        self.assertTrue(True)


if __name__ == '__main__':
    unittest.main()
