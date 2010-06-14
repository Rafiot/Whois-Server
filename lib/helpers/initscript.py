import os 
import sys
import ConfigParser
config = ConfigParser.RawConfigParser()
config.read("../../etc/whois-server.conf")
root_dir = config.get('global','root')
pid_path = os.path.join(root_dir,config.get('global','pids'))

import os
import subprocess

import syslog
syslog.openlog('Whois_Server', syslog.LOG_PID, syslog.LOG_USER)

"""
Standard functions used by the init scripts
"""

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
    pidpath = os.path.join(pid_path,processname + ".pid")
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
