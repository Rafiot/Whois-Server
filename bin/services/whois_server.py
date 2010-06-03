import SocketServer


import ConfigParser
config = ConfigParser.RawConfigParser()
config.read("../../etc/whois-server.conf")
import sys
import os 
root_dir =  config.get('global','root')
sys.path.append(os.path.join(root_dir,config.get('global','lib')))
from queries.whois_query import *

class WhoisServer(SocketServer.BaseRequestHandler ):
    
    def handle(self):
        query_maker = WhoisQuery(int(config.get('whois_server','redis_db')))
        while 1:
            query = self.request.recv(1024).strip()
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



server = SocketServer.ThreadingTCPServer(('localhost', 4343), WhoisServer)
server.serve_forever()
