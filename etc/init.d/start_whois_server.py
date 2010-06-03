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

import signal

import subprocess


def service_start(servicename = None):
    """
    Launch a Process
    """
    if servicename is not None :
        service = os.path.join(services_dir, servicename+".py")
        return subprocess.Popen(["python",service])
    return False

def writepid (processname = None, proc = None):
    """
    Append the pid to the pids-list of this process
    """
    processname = os.path.basename(processname)
    pidpath = os.path.join(pid_path,processname+".pid")

    if processname is not None and proc is not None:
        f = open (pidpath,"a")
        f.write(str(proc.pid)+'\n')
        f.close()
        return True
    else:
        return False

def pidof(processname = None):
    """
    Get the pid of a process 
    """
    processname = os.path.basename(processname)
    pidpath = os.path.join(pid_path,processname+".pid")
    if processname is not None and os.path.exists(pidpath):
        f = open (pidpath)
        pids = f.readlines()
        f.close()
        return pids
    else:
        return False

def rmpid (processname = None):
    """
    Delete the pids-file
    """
    processname = os.path.basename(processname)
    pidpath = os.path.join(pid_path,processname+".pid")
    if os.path.exists(pidpath):
        os.unlink(pidpath)
        return True
    else:
        return False


"""
Launch the fetching of the whois databases
"""

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
    
