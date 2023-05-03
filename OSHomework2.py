from agent import *
import os
import time

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


def check_is_scanned(md5_hash, file_):
    try:
        agent_get = agent.api_get_respo(agent, md5_hash,file_)
        if agent_get['response_code'] == 0:
            return False
        # if agent_get['response_code'] == -2:
        #     return False
        if agent_get['response_code'] == 1:
            return True
    except:
        pass

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
            print(md5_list)
            check_md5 = {}
            for i in md5_list.keys():
                print(all_md5_scanned.keys().__contains__(md5_list.get(i)))
                if not all_md5_scanned.keys().__contains__(md5_list.get(i)):
                    if md5_list.keys().__contains__(i):
                        #for j in md5_list.keys():
                            #all_md5_scanned.__setitem__(md5_list.get(i), i)
                            time.sleep(20)
                            print("Scanning : ", i)
                            check_md5 = check_is_scanned(md5_list.get(i),i)
                            if check_md5 == False:
                                scan_file = agent.api_conn_up(agent, i)
                                all_md5_scanned.__setitem__(md5_list.get(i), i)
                            else:
                                all_md5_scanned.__setitem__(md5_list.get(i), i)
                                pass
                # send the result to the server
        except Exception as e:
            print(e.with_traceback())
