__author__ = 'Fahad Al Summan'

# created by fahad at 5:30 PM 2/20/23
import json
import os

import requests
from hashlib import md5
import json
from server import *

files = os.listdir(".")




class agent:
    md5_file_list = []
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    def api_conn_up(self, file_name):
        print("Scan --->  {}".format(file_name))
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        # api_key = "b945f8860ef6b3b1646f1cc24d3444bb5e86fdb1ecf3e1d458b42159f3103b19"
        #api_key = "79276e440d8076d16b15e25755c4476dce54318dee3ba3d3c943119dc07fd421"
        api_key = "0a1effc9d808f113c635051d9733de3c4825b9ae1c44413d2e89a0d5ad88ee40"
        params = {'apikey': api_key}
        files = {'file': (file_name, open(file_name, 'rb'))}
        response = requests.post(url, files=files, params=params)
        print(response.json())
        return response.json()

    # check if the response code == 0 =>scan this file other wise get the response
    def api_get_respo(self, md5_file,file):
        # api_key = "b945f8860ef6b3b1646f1cc24d3444bb5e86fdb1ecf3e1d458b42159f3103b19" falusmma Key
        #api_key = "79276e440d8076d16b15e25755c4476dce54318dee3ba3d3c943119dc07fd421"
        # api_key = "729ff5ed0ccb4ca253725064d09ed606b846c810d9743105fad0e77baa903bd9"
        api_key = "0a1effc9d808f113c635051d9733de3c4825b9ae1c44413d2e89a0d5ad88ee40"
        resource = md5_file  # hash_file_md5
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'Accept': 'application/json','apikey': api_key, 'resource': resource}
        list_file_delete=[]
        try:
            response = requests.get(url, params=params)
            print(response.json())
            virus_check = self.check_percentage(self, response.json())
            is_delete = "This file has been deleted"
            data = {

                'data':f"md5[{response.json()['md5']}]",
                'file':f"file [{file}]",
                'is_virus':f"[{virus_check}]"

            }
            data_js = json.dumps(data)
            requests.post("http://127.0.0.1:8080/api/add", data=data,
                          headers={'Content-type': 'application/json', 'Accept': 'text/plain'})

            if virus_check == True:
                print("WE have found a virus in your directory")
                list_file_delete.append(response.json()['md5'])
                os.remove(file)
                print("This file has been deleted", file)
            return response.json()
        except Exception as e:
            print(e.with_traceback())

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
            return True
        else:
            print("Clear Dont Scan it again")
            return False

    def md5_directory_files(self,files):
        list_fmd5 = {}
        if len(files) >= 1:
            for i in files:
                if os.path.isfile(i):
                    md5_f = self.check_md5(self=agent, file=i)
                    if md5_f != None:
                        list_fmd5.__setitem__(i, md5_f)
        return list_fmd5

