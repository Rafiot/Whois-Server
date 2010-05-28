#!/usr/bin/python
# -*- coding: utf-8 -*-

import redis
import ConfigParser
config = ConfigParser.RawConfigParser()
config.read("../../etc/whois-server.conf")

import IPy
import re

class WhoisQuery():
    
    # subkeys - ARIN
    pocs_flag = ':pocs'
    orgid_flag = ':orgid'
    parent_flag = ':parent'
    subkeys_arin = [ pocs_flag, orgid_flag, parent_flag ]
    
    # subkeys - RIPE
    mntners_flag = ':mntners'
    persons_flag = ':persons'
    roles_flag = ':roles'
    aut_nums_flag = ':autnums'
    
    origin_flag = ':origin'
    irt_flag = ':irt'
    subkeys_ripe = [ mntners_flag, persons_flag, roles_flag, aut_nums_flag, origin_flag, irt_flag ]
    
    subkeys = subkeys_arin + subkeys_ripe
    
    def __init__(self):
        self.redis_whois_server = redis.Redis(db=int(config.get('whois_server','redis_db')) )
    
    def whois_asn(self, query):
        to_return = self.redis_whois_server.get(query)
        if not to_return:
            to_return = 'ASN not found.'
        else:
            to_return += self.get_all_informations(query)
        return to_return

    def __find_best_range(self, ip):
        to_return = None
        ranges = None
        key = str(ip)
        while not ranges:
            if self.ipv4 :
                key = re.findall('.*[.]', key)
            else: 
                key = re.findall('.*[:]', key)
            if len(key) != 0:
               key = key[0][:-1]
            else:
                break
            ranges = self.redis_whois_server.smembers(key)
        best_range = None
        for range in ranges:
            splitted = range.split('_')
            ip_int = ip.int()
            if best_range is not None:
                br_splitted = best_range.split('_')
                if int(splitted[0]) > int(br_splitted[0]) and int(splitted[1]) < int( br_splitted[1]):
                    best_range = range
            elif int(splitted[0]) <= ip_int and int(splitted[1]) >= ip_int:
                best_range = range
        if best_range is not None:
            to_return = self.redis_whois_server.get(best_range)
        return to_return

    def get_all_informations(self, key):
        to_return = ''
        for subkey in self.subkeys:
            list = self.redis_whois_server.smembers(key + subkey)
            for element in list:
                value = self.redis_whois_server.get(element)
                if value is not None:
                    to_return += '\n' + value
        return to_return

    def whois_ip(self, ip):
        ip = IPy.IP(ip)
        if ip.version() == 4:
            self.ipv4 = True
        else:
            self.ipv4 = False
        key = self.__find_best_range(ip)
        to_return = ''
        if not key:
            to_return += 'IP ' + str(ip) + ' not found.'
        else:
            to_return += self.redis_whois_server.get(key)
            to_return += self.get_all_informations(key)
        return to_return


if __name__ == "__main__":
    import os 
    import IPy
    import sys
    query_maker = WhoisQuery()
    
    def usage():
        print "arin_query.py query"
        exit(1)

    if len(sys.argv) < 2:
        usage()

    query = sys.argv[1]
    ip = None
    try:
        ip = IPy.IP(query)
    except:
        pass


    if ip:
        print(query_maker.whois_ip(ip))
    else:
       print(query_maker.whois_asn(query))
