import urllib, json
from urllib.request import urlopen
import re


#This function pull mitre json and send to local DB the new hash map
def getMitreDataFromUrl():
    mitre_hash_techniqe ={}

    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    json_url = urlopen(url)
    data = json.loads(json_url.read())



    for i in data['objects']:
        if 'x_mitre_data_sources' in i:
            if 'Windows event logs' in i['x_mitre_data_sources']:
                if 'Event ID' in i['x_mitre_detection']:
                    eventIds = getEventIds(i['x_mitre_detection'])
                    key = i['external_references'][0]['external_id']

                    if key in mitre_hash_techniqe.keys():

                        mitre_hash_techniqe[key].append(eventIds)
                    else:
                        mitre_hash_techniqe[key] = eventIds
    invertMitreHashMap(mitre_hash_techniqe)



#This function gets the x_mire_detection str.split string and return the event ids thet can be use with this techniqe
def getEventIds(description):
    eventIds = re.findall(r'\b\d+\b', description)
    for event in reversed(eventIds):
        if int(event) < 1100 or int(event) > 1108 and int(event) < 4608:
            eventIds.remove(event)
    eventIds = set(eventIds)
    return eventIds

def invertMitreHashMap(mitreMap):
    new_dic = {}
    for k, v in mitreMap.items():
        for x in v:
            new_dic.setdefault(x, []).append(k)

    print(new_dic)







#getMitreDataFromUrl()