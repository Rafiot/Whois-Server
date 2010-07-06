#!/usr/bin/python
# -*- coding: utf-8 -*-
import os 
import sys
import ConfigParser
config = ConfigParser.RawConfigParser()
config.read("../../etc/whois-server.conf")
root_dir =  config.get('global','root')
sys.path.append(os.path.join(root_dir,config.get('global','lib')))

import datetime

from abstract_init_whois_server import *
from parsers.arin_whois_parser import *

import IPy
import redis

import syslog
syslog.openlog('Init_ARIN', syslog.LOG_PID, syslog.LOG_USER)


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
        syslog.syslog(syslog.LOG_INFO, '============================')
        syslog.syslog(syslog.LOG_INFO, 'Pushing new database.')
        self.begin = datetime.datetime.now()
        InitWhoisServer.__init__(self)

    def push_helper_keys(self, key, redis_key, entry):
        parser = ARINWhois(entry)
        if key == self.net or key == self.v6net:
            self.__push_range(parser, redis_key)
        subkey = ':' + key[1:-1]
        if key != self.poc:
            self.push_entry(parser.pochandles, redis_key, self.pocs_flag, subkey)
        if key != self.orgid:
            self.push_entry(parser.orgid, redis_key, self.orgid_flag, subkey)
        self.push_entry(parser.parent, redis_key, self.parent_flag, subkey)

    def __push_range(self, parser, net_key):
        first = IPy.IP(parser.netrange[0][0])
        last = IPy.IP(parser.netrange[0][1])
        if first.version() == 4:
            ipv4 = True
        else:
            ipv4 = False
        self.push_range(first, last, net_key, ipv4)

    def push_into_db(self):
        intermediate_keys = self.total_keys
        syslog.syslog(syslog.LOG_DEBUG, 'Pushing ' + str(self.pending_keys) + ' main keys...')
        self.redis_whois_server = redis.Redis(db=int(config.get('whois_server','redis_db')) )
        for key, entries in self.keys.iteritems():
            while len(entries) > 0 :
                entry = entries.pop()
                if key == self.net or key == self.v6net:
                    redis_key = 'range:' + str(self.redis_whois_server.incr(uniq_range_id))
                else:
                    redis_key = re.findall(key + '[\s]*([^\s]*)', entry)[0]
                self.redis_whois_server.set(redis_key, entry)
                self.total_keys += 1 
                self.push_helper_keys(key, redis_key, entry)
        self.total_main_keys += self.pending_keys
        self.pending_keys = 0
        syslog.syslog(syslog.LOG_DEBUG, '...' + str(self.total_keys - intermediate_keys) + ' keys pushed.')
        syslog.syslog(syslog.LOG_DEBUG, str(self.total_main_keys) + ' main keys pushed until now.')
        syslog.syslog(syslog.LOG_INFO, str(self.total_keys) + ' keys pushed until now.')
        syslog.syslog(syslog.LOG_INFO, 'Running since ' + str(datetime.datetime.now() - self.begin))

if __name__ == "__main__":
    """
    $ time python init_arin.py 

    real	40m45.703s
    user	15m28.102s
    sys	3m6.500s

    14261242 keys
    """
    arin = InitARIN()
    files = arin.split()
    processes = []
    for file in files:
        p = Process(target=arin.dispatch_by_key, args=(file,))
        p.start()
        processes.append(p)
    for p in processes:
        p.join()
    arin.push_into_db()
    arin.clean_system()

