#!/usr/bin/python
# -*- coding: utf-8 -*-
# Needs redis-py from git! the stable version has a bug in keys()

from whois_query import WhoisQuery

class ARINQuery(WhoisQuery):
    
    # subkeys
    pocs_flag = ':pocs'
    orgid_flag = ':orgid'
    parent_flag = ':parent'
    subkeys = [ pocs_flag, orgid_flag, parent_flag ]
    
    
if __name__ == "__main__":
    import os 
    import IPy
    import sys
    query_maker = ARINQuery()
    
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
