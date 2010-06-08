# -*- coding: utf-8 -*-

import os
import cherrypy
from Cheetah.Template import Template

import ConfigParser
import sys
config = ConfigParser.RawConfigParser()
config.read("../etc/whois-server.conf")
root_dir =  config.get('global','root')
sys.path.append(os.path.join(root_dir,config.get('global','lib')))
from queries.whois_query import *

config_file = config.get('web','config_file')
templates = config.get('web','templates')
website_root = config.get('web','website_root')
css_file = config.get('web','css_file')


class Master(object):

    def default(self, query = ""):
        filename = os.path.join(website_root, templates, 'master.tmpl')
        self.template = Template(file = filename)
        self.template.title = 'index'
        self.template.css_file = css_file
        if query == "":
            self.template.query = 'IP or AS Number'
        else:
            self.template.entry = self.query_db(query)
            self.template.query = query
        return str(self.template)
    default.exposed = True
    
    def query_db(self, query):
        query_maker = WhoisQuery(int(config.get('whois_server','redis_db')))
        ip = None
        try:
            ip = IPy.IP(query)
        except:
            pass
        to_return = ''
        try:
            if ip:
                to_return = query_maker.whois_ip(ip)
            else:
                to_return = query_maker.whois_asn(query)
        except:
            to_return = 'Unable to contact the redis server'
        return to_return
        


if __name__ == "__main__":
    cherrypy.quickstart(Master(), config = config_file)

