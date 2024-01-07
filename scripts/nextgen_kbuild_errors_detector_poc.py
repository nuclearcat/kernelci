#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
'''
Retrieve nodes from staging.kernelci.org and check if there are new build errors
Detect only new build errors by line md5 hash
'''

import time
import requests
import json
import datetime
import hashlib
import os

AGE_DAYS = 7

hash_db = {}

def parse_log(log):
    hashes = []
    # if log empty? return empty array
    if log == None:
        return hashes
    # get hash for each line
    log = log.splitlines()
    for line in log:
        #print(f"Line: {line}")
        hash_object = hashlib.md5(line.encode())
        hashes.append(hash_object.hexdigest())
    return hashes

def retrieve_log(url):
    if not os.path.exists(".cache"):
        os.makedirs(".cache")
    # cache filename is just md5 of url
    hashid = hashlib.md5(url.encode()).hexdigest()
    cachefile = ".cache/" + hashid
    # if cache file exist - return content
    if os.path.exists(cachefile):
        with open(cachefile, 'r') as f:
            return f.read()
    r = requests.get(url)
    if r.status_code != 200:
        print("Error: ", r.status_code, r.text)
        return None
    # save to cache
    with open(cachefile, 'w') as f:
        f.write(r.text)
    return r.text

def retrieve_kernels():
    # date_str - 7 days old
    d = datetime.datetime.today() - datetime.timedelta(days=AGE_DAYS)
    date_str = d.strftime("%Y-%m-%dT%H:%M:%S.%f")
    url = "https://staging.kernelci.org:9000/latest/nodes?"
    condition = "created__gt=" + date_str;
    condition += "&limit=10000";
    url += condition
    print(url)
    r = requests.get(url)
    if r.status_code != 200:
        print("Error: ", r.status_code, r.text)
        return None
    j = r.json()
    return j['items']


def retrieve_build_errs(j):
    global hash_db
    print("Retrieving build errors for " + str(len(j)) + " nodes")
    for i in j:
        if 'artifacts' in i:
            if i['artifacts'] == None:
                continue
            if 'build_kimage_stderr.log' in i['artifacts']:
                log = retrieve_log(i['artifacts']['build_kimage_stderr.log'])
                hashes = parse_log(log)
                # verify if hash in hash_db, if not - show error log and add to hash_db
                new_error = 0
                for h in hashes:
                    if h in hash_db:
                        continue
                    else:
                        new_error = 1
                        hash_db[h] = 1
                if new_error == 1:
                    print("")
                    print(f"[{i['id']}: {i['revision']['url']} / {i['revision']['tree']} / {i['revision']['commit']}] New build errors: {log}")
                else:
                    print(".", end="", flush=True)


def main():
    j = retrieve_kernels()
    retrieve_build_errs(j)

if __name__ == "__main__":
    main()

