__author__ = 'Fahad Al Summan'

# created by fahad at 4:48 PM 2/20/23
###############NETWORK HOMEWORK######################
##### CSEC-380/480 Security Automation - Ryan Haley####
import os
import time

from agent import *
from server import *
import requests

'''
Finish AV scanner started in class
Requirements:
	    Architecture
		Agent
		Server
		Virustotal API
	    Must only submit new files (never before seen on your system) to
	VT Baseline your folder
        Sumbit only files that are seen after the baseline
	Must rescan folder every 5 minutes
	Must immediately notify the user if a malicious file is found
	Malicious is indicated by any result above 4 hits OR 5% of engines on VT
	Should notify the user after the check is complete
	https://developers.virustotal.com/reference
'''


def files_in_directory():
    return os.listdir(".")


def md5_directory_files(files):
    list_fmd5 = {}
    if len(files) >= 1:
        for i in files:
            if os.path.isfile(i):
                md5_f = agent.check_md5(self=agent, file=i)
                if md5_f != None:
                    list_fmd5.__setitem__(i, md5_f)
    return list_fmd5


def check_is_scanned(md5_hash):
    agent_get = agent.api_get_respo(agent, md5_hash)
    if agent_get['response_code'] == 0:
        return False
    if agent_get['response_code'] == -2:
        return False
    if agent_get['response_code'] == 1:
        return True


if __name__ == '__main__':
    all_md5_scanned = {}
    md5_list = {}
    status_report = {}
    isFirstScan = False
    files = files_in_directory()
    while (True):
        try:
            print("Directory will be scanned every 5 min")
            print("Scanning Directory")
            time.sleep(10)
            # I remove files from here
            if all_md5_scanned == None:
                for i in files:
                    if os.path.isfile(i):
                        if not md5_list.keys().__contains__(i):
                            print("Detect a new file", i)
            for i in files:
                if os.path.isfile(i):
                    if not md5_list.keys().__contains__(i):
                        print("Detect a new file", i)
            md5_list = md5_directory_files(files)
            check_md5 = {}
            for i in md5_list.keys():
                if not all_md5_scanned.keys().__contains__(i):
                    if md5_list.keys().__contains__(i):
                        for j in md5_list.keys():
                            check_md5 = check_is_scanned(md5_list.get(j))
                            if check_md5 == False:
                                scan_file = agent.api_conn_up(agent, j)
                                all_md5_scanned.__setitem__(md5_list.get(j), j)
                                isFirstScan = True
                            else:
                                all_md5_scanned.__setitem__(md5_list.get(j), j)
                # send the result to the server
        except Exception as e:
            pass


__author__ = 'Fahad Al Summan'

# created by fahad at 5:30 PM 2/20/23
import json

import requests
from hashlib import md5
import json
from server import *


class agent:
    md5_file_list = []
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    def api_conn_up(self, file_name):
        print("Scan {}".format(file_name))
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        # api_key = "b945f8860ef6b3b1646f1cc24d3444bb5e86fdb1ecf3e1d458b42159f3103b19"
        api_key = "79276e440d8076d16b15e25755c4476dce54318dee3ba3d3c943119dc07fd421"
        # api_key = "729ff5ed0ccb4ca253725064d09ed606b846c810d9743105fad0e77baa903bd9"
        params = {'apikey': api_key}
        files = {'file': (file_name, open(file_name, 'rb'))}
        response = requests.post(url, files=files, params=params)
        print(response.json())
        return response.json()

    # check if the response code == 0 =>scan this file other wise get the response
    def api_get_respo(self, md5_file):
        # api_key = "b945f8860ef6b3b1646f1cc24d3444bb5e86fdb1ecf3e1d458b42159f3103b19" falusmma Key
        api_key = "79276e440d8076d16b15e25755c4476dce54318dee3ba3d3c943119dc07fd421"
        # api_key = "729ff5ed0ccb4ca253725064d09ed606b846c810d9743105fad0e77baa903bd9"
        resource = md5_file  # hash_file_md5
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': api_key, 'resource': resource}
        response = requests.get(url, params=params)
        txt = response.text.encode("utf-8")
        js = json.loads(txt)
        virus_check = self.check_percentage(self, js)
        requests.post("http://192.168.1.140:8080/api/add", data=json.dumps(js),
                      headers={'Content-type': 'application/json', 'Accept': 'text/plain'})
        if virus_check == True:
            print("WE have found a virus in your directory")

            print("send request to server")
        print(js['response_code'])
        return js

    def check_md5(self, file):
        md_calc = md5()
        try:
            with open(file, "rb") as file_scan_md5:
                for byte_block in iter(lambda: file_scan_md5.read(4096), b""):
                    md_calc.update(byte_block)
            result_md5 = md_calc
            return result_md5.hexdigest()
        except:
            pass

    def check_percentage(self, response):
        positive = response['positives']
        if positive >= 4:
            print("Deleted")
            print(response)
            return True
        else:
            print("Clear Dont Scan it again")
            return False
