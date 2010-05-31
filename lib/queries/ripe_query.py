#!/usr/bin/python
# -*- coding: utf-8 -*-
# Needs redis-py from git! the stable version has a bug in keys()

import IPy
import re

from whois_query import WhoisQuery

class RIPEQuery(WhoisQuery):
    
    # subkeys
    mntners_flag = ':mntners'
    persons_flag = ':persons'
    roles_flag = ':roles'
    aut_nums_flag = ':autnums'
    
    origin_flag = ':origin'
    irt_flag = ':irt'
    subkeys = [ mntners_flag, persons_flag, roles_flag, aut_nums_flag, origin_flag, irt_flag ]
    
    
if __name__ == "__main__":
    import os 
    import sys
    query_maker = RIPEQuery()
    
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
