#!/usr/bin/python
import sys
import os 
import ConfigParser
config = ConfigParser.RawConfigParser()
config.read("../../etc/whois-server.conf")
root_dir =  config.get('global','root')
sys.path.append(os.path.join(root_dir,config.get('global','lib')))

import logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    datefmt='%a, %d %b %Y %H:%M:%S',
                    filename=os.path.join(root_dir,config.get('global','logfile_server')))


redis_db = int(config.get('whois_server','redis_db'))
host = config.get('whois_server','host')
port = int(config.get('whois_server','port'))

import SocketServer
from queries.whois_query import *

class WhoisServer(SocketServer.BaseRequestHandler ):
    def handle(self):
        logging.info(self.client_address[0] + ' is connected' )
        query_maker = WhoisQuery(redis_db)
        queries = 0
        while 1:
            query = self.request.recv(1024).strip()
            if query == '':
                logging.info(self.client_address[0] + ' is gone' )
#                break
            ip = None
            logging.debug('Query of ' + self.client_address[0] + ': ' + query)
            queries += 1
            try:
                ip = IPy.IP(query)
            except:
                pass
            if ip:
                response = query_maker.whois_ip(ip)
            else:
               response = query_maker.whois_asn(query)
            if queries % 10 == 0:
                logging.info(self.client_address[0] + ' made ' + str(queries) + ' queries.')
            self.request.send(response + '\n')



server = SocketServer.ThreadingTCPServer((host, port), WhoisServer)
server.serve_forever()
