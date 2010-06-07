#!/usr/bin/python
import sys
import os 
import ConfigParser
config = ConfigParser.RawConfigParser()
config.read("../../etc/whois-server.conf")
root_dir =  config.get('global','root')
sys.path.append(os.path.join(root_dir,config.get('global','lib')))

redis_db = int(config.get('whois_server','redis_db'))
host = config.get('whois_server','host')
port = int(config.get('whois_server','port'))

import SocketServer
from queries.whois_query import *

class WhoisServer(SocketServer.BaseRequestHandler ):
    def handle(self):
        query_maker = WhoisQuery(redis_db)
        while 1:
            query = self.request.recv(1024).strip()
            if query == '':
                continue
            ip = None
            try:
                ip = IPy.IP(query)
            except:
                pass
            if ip:
                response = query_maker.whois_ip(ip)
            else:
               response = query_maker.whois_asn(query)
            self.request.send(response + '\n')



server = SocketServer.ThreadingTCPServer((host, port), WhoisServer)
server.serve_forever()
