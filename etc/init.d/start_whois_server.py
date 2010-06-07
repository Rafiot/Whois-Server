#!/usr/bin/python
# -*- coding: utf-8 -*-
# Inspired by : http://gitorious.org/forban/forban/blobs/master/bin/forbanctl

import os 
import sys
import ConfigParser
config = ConfigParser.RawConfigParser()
config.read("../../etc/whois-server.conf")
root_dir = config.get('global','root')
sys.path.append(os.path.join(root_dir,config.get('global','lib')))

services_dir = os.path.join(root_dir,config.get('global','services'))
pid_path = os.path.join(root_dir,config.get('global','pids'))

import signal
import subprocess

from helpers.initscript import *

"""
Start the whois server 
"""

def service_start(servicename = None):
    """
    Launch a Process
    """
    if servicename is not None :
        service = os.path.join(services_dir, servicename+".py")
        return subprocess.Popen(["python",service])
    return False

def usage():
    print "start_whois_server.py (start|stop)"
    exit (1)

if len(sys.argv) < 2:
    usage()

service = 'whois_server'

if sys.argv[1] == "start":

    print "Starting sorting..."
    print service+" to start..."
    proc = service_start(servicename = service)
    writepid(processname = service, proc = proc)

elif sys.argv[1] == "stop":

    print "Stopping sorting..."
    pids = pidof(processname=service)
    if pids:
        print service+" to be stopped..."
        for pid in pids:
            try:
                os.kill(int(pid), signal.SIGKILL)
            except OSError, e:
                print service+  " unsuccessfully stopped"
        print service
        rmpid(processname=service)

else:
    usage()
    
