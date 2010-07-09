#!/usr/bin/python
# -*- coding: utf-8 -*-

import os 
import sys
import ConfigParser
config = ConfigParser.RawConfigParser()
config.read("../../etc/whois-server.conf")
root_dir =  config.get('global','root')
sys.path.append(os.path.join(root_dir,config.get('global','lib')))

whois_db = os.path.join(root_dir, config.get('global','whois_db'))
unpack_dir = os.path.join(root_dir, config.get('whois_server','unpack_dir'))
use_tmpfs = int(config.get('whois_server','use_tmpfs'))


import re
import redis 
from abc import ABCMeta, abstractmethod

from helpers.files_splitter import *
from make_ip_keys import *
from multiprocessing import Process

# key incremented for each new ip range
uniq_range_id = 'range_id'

class InitWhoisServer:
    """
    Generic functions to initialize the redis database for a particular whois server. 
    This class needs some variables: 
    - keys: the list of keys of the database 
        format: [[ '^key', [] ] , [ '^key', [] ] ... ]
    - archive_name: the name of the db dump, gzip compressed
    - dump_name: the name of the db dump, extracted
    """
    
    max_pending_keys = 100000
    pending_keys = 0
    
    __metaclass__ = ABCMeta    
    @abstractmethod
    def push_helper_keys(self, key, redis_key, entry):
        """
        Push all helper keys for a particular whois source
        for example: push a network corresponding to a particular entry
        """
        pass

    def push_entry(self, entry, redis_key, flag, subkey):
        if entry is not None:
            self.push_list_at_key(entry, redis_key, flag, subkey)
    
    def push_list_at_key(self, mylist, redis_key, flag, subkey):
        mylist = filter(None, mylist)
        mylist = list(set(mylist))
        main_key = redis_key + flag
        for elt in mylist:
            self.redis_whois_server.sadd(main_key, elt)
            self.total_keys +=1
#            self.redis_whois_server.sadd(elt + subkey, redis_key)

    def __init__(self):
        self.total_keys = 0
        self.total_main_keys = 0
        if use_tmpfs:
            tmpfs_size = config.get('whois_server','tmpfs_size')
            if not os.path.ismount(unpack_dir):
#                print('Mount the tmpfs directory')
                os.popen('mount -t tmpfs -o size=' + tmpfs_size + ' tmpfs ' + unpack_dir)
        self.extracted = os.path.join(unpack_dir,self.dump_name)

    def split(self):
        self.fs = FilesSplitter(self.extracted, int(config.get('global','init_processes')))
        return self.fs.fplit()
    
    def prepare(self):
        archive = os.path.join(self.whois_db,self.archive_name)
        os.popen('gunzip -c ' + archive + ' > ' + self.extracted)
    
    def dispatch_by_key(self, file):
        entry = ''
        f = open(file)
        for line in f:
            if line == '\n':
                if len(entry) > 0 and re.match('^#', entry) is None:
                    first_word = '^' + re.findall('(^[^\s]*).*',entry)[0]
                    entries = self.keys.get(first_word, None)
                    if entries is not None:
                        entries.append(entry)
                    else:
                        pass
#                        print entry
                entry = ''
                self.pending_keys += 1
                if self.pending_keys >= self.max_pending_keys:
                    self.push_into_db()
            else :
                entry += line
        self.push_into_db()
    
    def clean_system(self):
        if use_tmpfs:
            if os.path.ismount(self.unpack_dir) is not None:
                print('Umount the tmpfs directory')
                os.popen('umount ' + self.unpack_dir)
        else:
#            os.unlink(extracted)
            pass

    def push_range(self, first, last, net_key, ipv4):
        range_key = str(first.int()) + '_' + str(last.int())
        first = str(first)
        last = str(last)
        maker = MakeIPKeys(ipv4)
        intermediate_sets = maker.intermediate_sets(first, last)
        for intermediate_set in intermediate_sets:
            self.redis_whois_server.sadd(intermediate_set, range_key)
            self.total_keys +=1
        self.redis_whois_server.set(range_key, net_key)
        self.total_keys +=1
