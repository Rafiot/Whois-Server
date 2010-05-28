#!/usr/bin/python
# -*- coding: utf-8 -*-

from abstract_init_whois_server import *
from parsers.arin_whois_parser import *

import IPy
import redis

class InitARIN(InitWhoisServer):
    
    orgid = '^OrgID:'
    net = '^NetHandle:'
    v6net = '^V6NetHandle:'
    ash = '^ASHandle:'
    poc = '^POCHandle:'


    pocs_flag = ':pocs'
    orgid_flag = ':orgid'
    parent_flag = ':parent'
    subkeys = [ pocs_flag, orgid_flag, parent_flag ]
    
    keys =  {
        net    : [] , 
        orgid  : [] , 
        v6net  : [] ,
        ash    : [] ,
        poc    : []  }
        
    archive_name = "arin_db.txt.gz"
    dump_name = "arin_db.txt"

    def __init__(self):
        InitWhoisServer.__init__(self)
    
    def push_poc(self, parser, redis_key, subkey):
        pochandles = parser.pochandles
        if pochandles is not None:
            self.push_list_at_key(pochandles, redis_key, self.pocs_flag, subkey)

    def push_origid(self, parser, redis_key, subkey):
        orgid = parser.orgid
        if orgid is not None:
            self.push_list_at_key(orgid, redis_key, self.orgid_flag, subkey)

    def push_parent(self, parser, redis_key, subkey):
        parent = parser.parent
        if parent is not None:
            self.push_list_at_key(parent, redis_key, self.parent_flag, subkey)

    def push_helper_keys(self, key, redis_key, entry):
        parser = ARINWhois(entry,  key)
        if key == self.net or key == self.v6net:
            self.__push_range(parser, redis_key)
        subkey = ':' + key[1:-1]
        self.push_poc(parser, redis_key, subkey)
        self.push_origid(parser, redis_key, subkey)
        self.push_parent(parser, redis_key, subkey)

    def __push_range(self, parser, net_key):
        first = IPy.IP(parser.netrange[0][0])
        last = IPy.IP(parser.netrange[0][1])
        if first.version() == 4:
            ipv4 = True
        else:
            ipv4 = False
        self.push_range(first, last, net_key, ipv4)

    def push_into_db(self):
        self.redis_whois_server = redis.Redis(db=int(config.get('whois_server','redis_db')) )
        for key, entries in self.keys.iteritems():
            print('Begin' + key)
            while len(entries) > 0 :
                entry = entries.pop()
                # TODO: be sure that if the key is on two lines (some inetnum), it works 
                redis_key = re.findall(key + '[\s]*([^\s]*)', entry)[0]
                self.redis_whois_server.set(redis_key, entry)
                self.push_helper_keys(key, redis_key, entry)
        self.pending_keys = 0


if __name__ == "__main__":
    """
    $ time python init_arin.py 

    real	32m46.930s
    user	12m42.908s
    sys	2m14.784s

    12197608 keys
    """
    arin = InitARIN()
    arin.start()
