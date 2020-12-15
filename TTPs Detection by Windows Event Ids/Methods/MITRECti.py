import json
from urllib.request import urlopen
import re


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
