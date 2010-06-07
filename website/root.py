#!/usr/bin/env python

import os
import cherrypy
from Cheetah.Template import Template

import ConfigParser
import sys
config = ConfigParser.RawConfigParser()
config.read("../etc/whois-server.conf")
root_dir =  config.get('global','root')
sys.path.append(os.path.join(root_dir,config.get('global','lib')))

config_file = config.get('web','config_file')

from queries.whois_query import *

class Root(object):
    query_form = \
                """
                Please enter your query
                <form method="POST" action=".">
                  <input type="text" name="query" value="$query">
                  <input type="submit" value="Submit">
                </form> <br/>
                """

    def index(self, query = ""):
        entry = None
        if query == "":
            query = 'IP or AS Number'
            template = Template(self.query_form)
        else:
            entry = self.query_db(query)
            template = Template(self.query_form + "Your last query was $query.")
        template.query = query
        to_return = str(template)
        if entry is not None:
            to_return += '<br/>' + '<pre>' + entry + '</pre>'
        return to_return
    index.exposed = True
    
    def query_db(self, query):
        query_maker = WhoisQuery(int(config.get('whois_server','redis_db')))
        ip = None
        try:
            ip = IPy.IP(query)
        except:
            pass
        to_return = ''
        if ip:
            to_return = query_maker.whois_ip(ip)
        else:
           to_return = query_maker.whois_asn(query)
        
        return to_return


if __name__ == "__main__":
    cherrypy.quickstart(Root(), config = config_file)
