import json
import urllib.request
from urllib.request import urlopen
import re
import sqlite3
import os.path
#-------------
import os, time
import http.client
import sys
import pickle
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
import yaml
## importing socket module
import socket

#from git import Repo



# This function pull mitre json and send to local DB the new hash map
def get_mitre_cti_hash_map():
    def load_windows_event_ids():
        try:
            pattern_file = open("windows-event-ids.txt")
            for line in pattern_file:
                line = line.strip()
                line_split = line.split('\t', maxsplit=2)
                event_id_ = line_split[1]
                header_ = line_split[2]
                pattern_dict[header_] = event_id_
            #print(pattern_dict)
        except:
            print("Error - failed to open the file windows-event-ids.txt")
            exit()

    def search_pattern(text):
        for header in pattern_dict.keys():
            if 'x_mitre_detection' in text.keys():
                for word in str(header).split(' '):
                    if word.lower() not in filter_words and word in text['x_mitre_detection']:
                        technique = text['external_references'][0]['external_id']
                        matched_words.append(word)
                        # print(text['x_mitre_detection'])
                        if technique in mitre_hash_technique.keys():
                            mitre_hash_technique[technique].append(pattern_dict[header])
                        else:
                            mitre_hash_technique[technique] = list(pattern_dict[header])

    pattern_dict = {}
    mitre_hash_technique = {}
    matched_words = []
    filter_words = (
        "a", "or", "to", "the", "for", "an", "its", "and", "of", "in", "from", "was", "on", "it", "has", "have",
        "been", "did", "not", "that", "with", "are", "as", "be", "this", "is", "now", "id", "get", "can", "no",
        "if", "get", "by", "after", "into", "up", "some", "does", "more", "see", "being", "made", "when", "only",
        "those", "but", "while", "other", "one", "per", "were", "will", "met", "could", "user", "users", "them", "they", "which",)
    load_windows_event_ids()
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
    #print(mitre_hash_technique)
    matched_words = set(matched_words)
    print(matched_words)
    print("inverting------")
    return invert_mitre_hash_map(mitre_hash_technique)
    # return mitre_hash_technique


# This function gets the x_mire_detection str.split string and return the event ids thet can be use with this techniqe
def get_event_ids(description):
    eventIds = re.findall(r'\b\d+\b', description)
    for event in reversed(eventIds):
        if int(event) < 1100 or 1108 < int(event) < 4608:
            eventIds.remove(event)
    eventIds = set(eventIds)
    return list(eventIds)


def invert_mitre_hash_map(mitre_hash_map):
    new_dic = {}
    print("original hash map:")
    print(mitre_hash_map)
    print("-------------\n\n")
    for k, v in mitre_hash_map.items():
        for x in v:
            if int(x) not in new_dic.keys():
                new_dic[int(x)] = list(k)
            elif k not in new_dic[int(x)]:
                new_dic[int(x)].append(k)

    print(new_dic)
    return new_dic


# This function save the mitre cti tuple to Mitre_CTI.db file
# Also this function make update for mitre cti db.
def save_mitre_cti_to_db():
    conn = sqlite3.connect("Databases/Mitre_CTI.db")
    cur = conn.cursor()
    create = "CREATE TABLE IF NOT EXISTS mitre_cti( event_id INT, ttp TEXT);"
    cur.execute(create)  # execute SQL commands
    conn.commit()

    mitre_cti_data = get_mitre_cti_hash_map()
    mitre_cti_data = [(int(i), str(mitre_cti_data[i])) for i in mitre_cti_data]
    insert_command = "INSERT INTO mitre_cti VALUES(?,?);"

    cur.executemany(insert_command, mitre_cti_data)
    conn.commit()

    #save to db the lest modify date of the ttps.
    create = "CREATE TABLE IF NOT EXISTS mitre_cti_last_modify(ttp TEXT, date TEXT);"
    cur.execute(create)  # execute SQL commands
    conn.commit()

    mitre_cti_last_modify = get_lest_modified_date()
    #print_check(mitre_cti_last_modify)
    mitre_cti_last_modify = [(str(i), str(mitre_cti_last_modify[i])) for i in mitre_cti_last_modify]
    #print_check(mitre_cti_last_modify)
    insert_command = "INSERT INTO mitre_cti_last_modify VALUES(?,?);"


    cur.executemany(insert_command, mitre_cti_last_modify)
    conn.commit()
    # show_db()


# this function shwos the data inside Mitre_CTI.db
def show_db():
    conn = sqlite3.connect("Databases/Mitre_CTI.db")
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table';")  # show all the tables in the .db file
    print("Mitre_CTI.db__________________________________________________________________________________")
    print(cur.fetchall())
    cur.execute("SELECT * FROM mitre_cti")  # show all the data inside mitre_cti table/
    print(cur.fetchall())
    names = list(map(lambda x: x[0], cur.description))  # show all the columns names
    print(names)
    print("Mitre_CTI.db_end______________________________________________________________________________")


# TODO to remove to ' "['T1558.004']" ' and change it to -> 'T1558.004'
def get_mitre_cti_hash_map_from_db():
    mitreCTIHashMap = {}
    if not os.path.exists("Databases/Mitre_CTI.db"):  # or "Databases/Mitre_CTI.db"
        save_mitre_cti_to_db()
    try:
        sqliteConnection = sqlite3.connect("Databases/Mitre_CTI.db")
        cursor = sqliteConnection.cursor()
        sqlite_select_Query = "select event_id, ttp from mitre_cti"
        cursor.execute(sqlite_select_Query)
        record = cursor.fetchall()
        # print(mitreCTIHashMap)
        for rec in record:
            if rec[0] in mitreCTIHashMap.keys():
                mitreCTIHashMap[int(rec[0])].append(rec[1])
            else:
                # print(rec[0])
                mitreCTIHashMap[int(rec[0])] = [rec[1]]
        cursor.close()
        sqliteConnection.close()
        return mitreCTIHashMap
    except sqlite3.Error as error:
        print("error while connecting to sqlite ", error)


def get_modify_date_from_db():
    mitre_modify_hash_map = {}
    if not os.path.exists("Databases/Mitre_CTI.db"):  # or "Databases/Mitre_CTI.db"
        save_mitre_cti_to_db()
    try:
        sqliteConnection = sqlite3.connect("Databases/Mitre_CTI.db")
        cursor = sqliteConnection.cursor()
        sqlite_select_Query = "select ttp, date from mitre_cti_last_modify"
        cursor.execute(sqlite_select_Query)
        record = cursor.fetchall()
        # print(mitreCTIHashMap)
        for rec in record:
            if rec[0] in mitre_modify_hash_map.keys():
                mitre_modify_hash_map[rec[0]].append(rec[1])
            else:
                # print(rec[0])
                mitre_modify_hash_map[rec[0]] = [rec[1]]
        cursor.close()
        sqliteConnection.close()
        return mitre_modify_hash_map
    except sqlite3.Error as error:
        print("error while connecting to sqlite ", error)

def check_for_update():

    count = 0
    # get last modified data from MITRE CTI github
    modified_hash_map_from_mitre_cti = get_lest_modified_date()

    # get last modified data from MITRE CTI local db
    modified_hash_map_from_db = get_modify_date_from_db()

    for i in modified_hash_map_from_db:
        if i in modified_hash_map_from_mitre_cti:
            count += 1
        else:
            return False

    return True


def get_lest_modified_date():
    modified_hash_map = {}

    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    json_url = urlopen(url)
    data = json.loads(json_url.read())

    for i in data['objects']:
        if 'modified' in i:
            if 'external_references' in i:
                if 'external_id' in i['external_references'][0]:
                    date = i['modified']
                    key = i['external_references'][0]['external_id']
                    if key in modified_hash_map.keys():
                        modified_hash_map[key].append(date)
                    else:
                        modified_hash_map[key] = []
                        modified_hash_map[key].append(date)

                    #print("TTTTTTrue")

    #print(modified_hash_map)
    return modified_hash_map


def print_check(x):
    print("---------------------------------------------------------------------------------------------------")
    print("_+_++_++_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_++_+_+_+_+_+_+_+_+_++_+_+_+_+_+_+_")
    print("_+_++_++_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_++_+_+_+_+_+_+_+_+_++_+_+_+_+_+_+_")
    print("_+_++_++_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_++_+_+_+_+_+_+_+_+_++_+_+_+_+_+_+_")
    print(x)
    print("_+_++_++_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_++_+_+_+_+_+_+_+_+_++_+_+_+_+_+_+_")
    print("_+_++_++_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_++_+_+_+_+_+_+_+_+_++_+_+_+_+_+_+_")
    print("_+_++_++_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_++_+_+_+_+_+_+_+_+_++_+_+_+_+_+_+_")
    print("---------------------------------------------------------------------------------------------------")
