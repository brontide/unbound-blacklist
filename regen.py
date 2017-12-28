#!/usr/bin/env python3

import requests

BLACKLIST = 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts' 

ADDED_HOSTS = 'local_blacklist.txt'

WHITELIST = 'local_whitelist.txt'

def file_to_set(filename):
    '''
    Each line not starting with a # is a 
    hostname that we should add to the set
    '''
    myset = set()
    try:
        for line in open(filename):
            line = line.strip()
            if line.startswith("#"): continue
            hostname = line
            try:
                hostname, rest = hostname.split(None, 1)
            except:
                pass
            myset.add(hostname.lower())
    except:
        pass
    return myset
        

def url_to_set(url):
    '''
    Each line starting with 0.0.0.0 is a hostname
    '''
    out = requests.get(url)
    myset = set()
    for line in out.text.splitlines():
        line = line.strip()
        if line.startswith("#"): continue
        if not line.startswith('0.0.0.0 '): continue
        try:
            ip, hostname, *rest = line.split()
            myset.add(hostname.lower())
        except:
            pass
    return myset

def sort_dns(item):
    return '.'.join(item.split('.')[::-1])


from pprint import pprint

blacklist = url_to_set(BLACKLIST)
local_blacklist = file_to_set(ADDED_HOSTS)

bs = sorted(blacklist|local_blacklist, key=sort_dns)

for host in bs:
    print(f"local-zone: {host:>50} refuse")
