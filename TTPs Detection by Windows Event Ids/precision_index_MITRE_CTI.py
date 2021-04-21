import Methods.EventList as EventList
import Methods.MITRECti as MITRECti
import Methods.Malware as Malware
from Util.GetTTPs import get_ttp_from_event_ids

def get_mitre_cti_result(event_id):
    mitreMap = {}
    mitreMap = MITRECti.get_mitre_cti_hash_map_from_db()
    event_ids = []
    event_ids.append(event_id)
    return get_ttp_from_event_ids(mitreMap, event_ids)

def get_event_list_result(event_id):
    eventlistMap = {}
    eventlistMap = EventList.get_event_list_hash_map()
    return get_ttp_from_event_ids(eventlistMap, event_id)

def get_malware_result(event_id):
    malwareMap = {}
    malwareMap = Malware.get_Malware_Archaeology_HashMap_from_db()
    return get_ttp_from_event_ids(malwareMap, event_id)


def get_mitre_cti_measure():
    mitre_cti_res = {}
    event_list_res = {}
    malware_res = {}
    count_mite_to_event_list = []
    count_mite_to_malware = []

    mitreMap = MITRECti.get_mitre_cti_hash_map_from_db()
    print(mitreMap)
    print(get_mitre_cti_result(4768))
    for event in mitreMap:
       # if event in mitre_cti_res.keys():
       # print("event = " + str(event))
        mitre_cti_res[event] = get_mitre_cti_result(event)
        event_list_res[event] = get_event_list_result(event)
       # print("ggggggg ")
        #print(get_event_list_result(event))
        malware_res[event] = get_malware_result(event)

    for event in mitre_cti_res:
        print("event = " + str(event))
        if if_in(mitre_cti_res[event], event_list_res[event]):                          #if mitre_cti_res[event] in event_list_res[event]:
            count_mite_to_event_list.append(1)
        else:
            count_mite_to_event_list.append(0)

        if if_in(mitre_cti_res[event], malware_res[event]):                            #if mitre_cti_res[event] in malware_res[event]:
            count_mite_to_malware.append(1)
        else:
            count_mite_to_malware.append(0)
    #count = 0

    length_mite_to_event_list = len(count_mite_to_event_list)
    in_mite_to_event_list = sum(count_mite_to_event_list)
    out_mite_to_event_list = length_mite_to_event_list - in_mite_to_event_list

    length_mite_to_malware = len(count_mite_to_malware)
    in_mitre_to_malware = sum(count_mite_to_malware)
    out_mitre_to_malware = length_mite_to_malware - in_mitre_to_malware

    print("length_mite_to_event_list = " + str(length_mite_to_event_list))
    print("in_mite_to_event_list = " + str(in_mite_to_event_list))
    print("out_mite_to_event_list = " + str(out_mite_to_event_list))

    print("----------------------------------------------------------------------")

    print("length_mite_to_malware = " + str(length_mite_to_malware))
    print("in_mitre_to_malware = " + str(in_mitre_to_malware))
    print("out_mitre_to_malware = " + str(out_mitre_to_malware))



def if_in(in_event, out_event):
    count = 0
    print("in event = " + str(in_event))
    print("out_event = " + str(out_event))


    for ttp in in_event:
        #for ttp in ttplist:
        if len(out_event) != 0:
            for item in out_event:
                #print("-----item = " + str(item))
                #print("+++++ttp = " + str(ttp[2:len(ttp)-2]))
                if len(item) > 1 and type(item) != str:
                    for i in item:
                        print("iiiiiiii i = "+str(i))
                        if i == ttp[2:len(ttp)-2]:
                            count = count + 1
                elif item == ttp[2:len(ttp)-2]:
                    count = count + 1
        #return False
    print("count = " + str(count))
    if count > 0:
        return True
    else:
        return False

get_mitre_cti_measure()


""" """