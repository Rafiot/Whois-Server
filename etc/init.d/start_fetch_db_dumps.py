#!/usr/bin/python
# -*- coding: utf-8 -*-
# Inspired by : http://gitorious.org/forban/forban/blobs/master/bin/forbanctl

import os 
import sys
import ConfigParser
config = ConfigParser.RawConfigParser()
config.read("../whois-server.conf")
root_dir = config.get('global','root')
sys.path.append(os.path.join(root_dir,config.get('global','lib')))

services_dir = os.path.join(root_dir,config.get('global','services'))
pid_path = os.path.join(root_dir,config.get('global','pids'))

import logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    datefmt='%a, %d %b %Y %H:%M:%S',
                    filename=os.path.join(root_dir,config.get('global','logfile_fetching')))

import signal
import subprocess

"""
Launch the fetching of the whois databases
"""

def service_start_once(servicename = None, param = None, processname = None):
    processname = os.path.basename(processname)
    pidpath = os.path.join(pid_path,processname+".pid")
    if not os.path.exists(pidpath):
        proc = service_start(servicename, param)
        writepid(processname, proc)
    else:
        print(param + ' already running on pid ' + str(pidof(processname)[0]))
        logging.info(param + ' already running on pid ' + str(pidof(processname)[0]))

def service_start(servicename = None, param = None):
    """
    Launch a Process
    """
    if servicename is not None :
        service = servicename+".py"
        if not param:
            proc =  subprocess.Popen(["python",service])
        else:
            proc =  subprocess.Popen(["python",service, param])
        return proc
    return False

service = os.path.join(services_dir, "fetch_db_dumps")

options = \
        {'RIPE'     :   'ftp://ftp.ripe.net/ripe/dbase/RIPE.CURRENTSERIAL ftp://ftp.ripe.net/ripe/dbase/ripe.db.gz'}

def usage():
    print "start_fetch_db_dumps.py (start|stop)"
    exit (1)

if len(sys.argv) < 2:
    usage()

if sys.argv[1] == "start":
    for name, option in options.iteritems():
        print('Start fetching of ' + name)
        logging.info('Start fetching of ' + name)
        proc = service_start_once(servicename = service, param = option,  processname = service + name)
elif sys.argv[1] == "stop":
    for name in options.keys():
        print('Stop fetching of ' + name)
        logging.info('Stop fetching of ' + name)
        pid = pidof(processname=service + name)
        if pid:
            pid = pid[0]
            try:
                os.kill(int(pid), signal.SIGKILL)
            except OSError, e:
                print(name +  " unsuccessfully stopped")
                logging.info(name +  " unsuccessfully stopped")
            rmpid(processname=service + name)
        else:
            print('No running fetching processes')
            logging.info('No running fetching processes')
else:
    usage()
