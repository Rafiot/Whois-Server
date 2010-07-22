#!/usr/bin/python
# -*- coding: utf-8 -*-
import os 
import sys
import ConfigParser
config = ConfigParser.RawConfigParser()
config.read("../../etc/whois-server.conf")
root_dir =  config.get('global','root')
sys.path.append(os.path.join(root_dir,config.get('global','lib')))

from abstract_init_whois_server import *
from parsers.parsers import *
import filecmp
import shutil
import datetime

import os
import redis
import re
import IPy

import syslog
syslog.openlog('Init_RIPE', syslog.LOG_PID, syslog.LOG_USER)

class InitRIPE(InitWhoisServer):
    inetnum = '^inetnum:'
    inet6num = '^inet6num:'
    person = '^person:'
    role = '^role:'
    domain = '^domain:'
    aut_num = '^aut-num:'
    route = '^route:'
    route6 = '^route6:'
    as_set = '^as-set:'
    rtr_set = '^rtr-set:'
    route_set = '^route-set:'
    poetic_form = '^poetic-form:'
    poem ='^poem:' 
    peering_set ='^peering-set:'
    limerick ='^limerick:'
    key_cert = '^key-cert:'
    inet_rtr ='^inet-rtr:'
    filter_set ='^filter-set:'
    irt = '^irt:'
    mntner = '^mntner:' 
    organisation = '^organisation:'
    as_block = '^as-block:'
    
    mntners_flag = ':mntners'
    persons_flag = ':persons'
    roles_flag = ':roles'
    aut_nums_flag = ':autnums'
    
    origin_flag = ':origin'
    irt_flag = ':irt'    

    keys =  {
         inetnum       : [] ,
#         domain        : [] ,
         inet6num      : [] ,
         aut_num       : [] ,
         route         : [] ,
         route6        : [] ,
#         as_block      : [] , #FIXME: Not used for now.
         as_set        : [] ,
         rtr_set       : [] ,
         route_set     : [] ,
#         poetic_form   : [] ,
#         poem          : [] ,
         peering_set   : [] ,
#         limerick      : [] ,
#         key_cert      : [] ,
         inet_rtr      : [] ,
         filter_set    : [] , 
        #Dummy
         irt           : [] , 
         mntner        : [] , 
         organisation  : [] , 
         person        : [] , 
         role          : []  }

    nic_keys = [ person , role ]    
    range_keys = [ inetnum , inet6num ]  

    archive_name = "ripe.db.dummy.gz"
    dump_name = "ripe.db.dummy"
    serial = "RIPE.CURRENTSERIAL"

    def __init__(self):
        syslog.syslog(syslog.LOG_INFO, '============================')
        syslog.syslog(syslog.LOG_INFO, 'Pushing new database.')
        self.begin = datetime.datetime.now()
        InitWhoisServer.__init__(self)
        self.serial = os.path.join(whois_db,self.serial)
        self.last_parsed_serial = os.path.join(whois_db, self.serial + "_last")

    def new_file(self):
        if os.path.exists(last_parsed_serial) and filecmp.cmp(serial, last_parsed_serial):
            return False
        return True
 
    def  copy_serial(self):
        shutil.copy(self.serial,self.last_parsed_serial)

    def split_inline_AS(self, list):
        asn = []
        if list is not None:
          for l in list:
              str = re.findall('(?:(?:AS|as)([\d\w-]*))',l)
              for s in str:
                  s = 'AS' + s
              asn.extend(str)
        return asn
    
    def split_inline_mnt(self, list):
        mnt = []
        if list is not None:
          for l in list:
              str = re.split('[ ,]*', l)
  #            str = re.findall('(RIPE-[\d\w]*-MNT)',l)
              mnt.extend(str)
        return mnt

    def split_inline_persons(self, list):
        persons = []
        if list is not None:
          for l in list:
              str = re.split('[ ,]*', l)
  #            str = re.findall('([\d\w]*-RIPE)',l)  
              persons.extend(str)
        return persons

    def push_helper_keys(self, key, redis_key, entry):
        parser = Whois(entry, 'whois.ripe.net')
        subkey = ':' + key[1:-1]
        if key == self.inetnum:
            self.ipv4 = True
            self.__push_range_v4(parser, redis_key)
        elif key == self.inet6num:
            self.ipv4 = False
            self.__push_range_v6(parser, redis_key)
        
        if key not in self.nic_keys :
            persons = self.split_inline_persons(parser.persons)
            self.push_entry(persons, redis_key, self.persons_flag, subkey)
        if key != self.irt:
            self.push_entry(parser.mnt_irt, redis_key, self.irt_flag, subkey)
        if key != self.mntner:
            mntners = self.split_inline_mnt(parser.mntners)
            self.push_entry(mntners, redis_key, self.mntners_flag, subkey)
        if key != self.aut_num:
            aut_nums = self.split_inline_persons(parser.aut_nums)
            self.push_entry(aut_nums, redis_key, self.aut_nums_flag, subkey)
        
        self.push_entry(parser.origin, redis_key, self.origin_flag, subkey)

    def ugly_fix_false_ips(self, subnet):
        # Hack in case the subnet is false in the db...
        splitted_subnet = subnet.split('/')
        splitted_subnet[0] = str(IPy.IP(splitted_subnet[0]))
        i = len(splitted_subnet[0]) - 1 
        while(splitted_subnet[0][i] != ':'):
            i -= 1
        ip = splitted_subnet[0][0:i+1] + '/'
        subnet = ip + splitted_subnet[1]
        try:
            network = IPy.IP(subnet)
        except:
            splitted_subnet = subnet.split('/')
            ip = splitted_subnet[0] + '/'
            i = int(splitted_subnet[1])
            while i <= 128:
                subnet = ip + str(i)
                i += 1
                try:
                    network = IPy.IP(subnet)
                    break
                except:
                    continue
        return network

    def __push_range_v6(self, parser, net_key):
        subnet = parser.inet6num[0]     
        try:
            network = IPy.IP(subnet)
        except: 
            network = self.ugly_fix_false_ips(subnet)
        first = network.net()
        last = network.broadcast()
        self.push_range(first, last, net_key, self.ipv4)

    def __push_range_v4(self, parser, net_key):
        first = IPy.IP(parser.inetnum[0][0])
        last = IPy.IP(parser.inetnum[0][1])
        self.push_range(first, last, net_key, self.ipv4)
    
    # We need a particular push function: some of the 'keys' are not really keys... : 
    # person is a name, and role is... something we want the nic-hdl:person and nic-hdl:role as key into redis
    def push_into_db(self):
        intermediate_keys = self.total_keys
        syslog.syslog(syslog.LOG_DEBUG, 'Pushing ' + str(self.pending_keys) + ' main keys...')
        self.redis_whois_server = redis.Redis(db=int(config.get('whois_server','redis_db')) )
        for key, entries in self.keys.iteritems():
            while len(entries) > 0 :
                redis_key = ''
                entry = entries.pop()
                if key in self.nic_keys:
                    redis_key = re.findall('\nnic-hdl:[\s]*([^\s]*)', entry)[0]
                    redis_key += ':' + key[1:-1]
                    self.redis_whois_server.set(redis_key, entry)
                elif key in self.range_keys:
                    redis_key = 'range:' + str(self.redis_whois_server.incr(uniq_range_id))
                    self.redis_whois_server.set(redis_key, entry)
                else:
                    redis_key = re.findall(key + '[\s]*([^\s]*)', entry)[0]
                    self.redis_whois_server.set(redis_key, entry)
                self.push_helper_keys(key, redis_key, entry)
        self.total_main_keys += self.pending_keys
        self.pending_keys = 0
        syslog.syslog(syslog.LOG_DEBUG, '...' + str(self.total_keys - intermediate_keys) + ' keys pushed.')
        syslog.syslog(syslog.LOG_DEBUG, str(self.total_main_keys) + ' main keys pushed until now.')
        syslog.syslog(syslog.LOG_INFO, str(self.total_keys) + ' keys pushed until now.')
        syslog.syslog(syslog.LOG_INFO, 'Running since ' + str(datetime.datetime.now() - self.begin))


if __name__ == "__main__":
    """
    real	48m39.926s
    user	21m28.861s
    sys	3m32.661s

    15496753 keys
    """
    ripe = InitRIPE()
    files = ripe.split()
    processes = []
    for file in files:
        p = Process(target=ripe.dispatch_by_key, args=(file,))
        p.start()
        processes.append(p)
    for p in processes:
        p.join()
    ripe.push_into_db()
    ripe.clean_system()
