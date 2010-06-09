#!/usr/bin/python
import os 
import sys
import ConfigParser
config = ConfigParser.RawConfigParser()
config.read("../../etc/whois-server.conf")
whois_dir = os.path.join(config.get('global','root'),config.get('global','whois_db'))

import logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    datefmt='%a, %d %b %Y %H:%M:%S',
                    filename=os.path.join(root_dir,config.get('global','logfile_fetching')))

import filecmp
import time
import urllib

"""
Fetch the db dump
"""


sleep_timer = int(config.get('global','sleep_timer'))

def usage():
    print "fetch_db_dumps.py serial url"
    exit (1)

if len(sys.argv) < 2:
    usage()

args = sys.argv[1].split(' ')
serial_name = os.path.basename(args[0])
db_name = os.path.basename(args[1])

temporary_dir = os.path.join(whois_dir, config.get('whois_server','temp_dir'))
temporary_serial_file = os.path.join(temporary_dir, serial_name)
temporary_db_file = os.path.join(temporary_dir, db_name)

serial_file = os.path.join(whois_dir, serial_name)
db_file = os.path.join(whois_dir, db_name)

while 1:
    urllib.urlretrieve(args[0], temporary_serial_file)
    new_db = True
    if os.path.exists(serial_file) and filecmp.cmp(temporary_serial_file, serial_file):
        new_db = False
    if new_db:
        logging.info('New ' + db_name)
        urllib.urlretrieve(args[1], temporary_db_file)
        os.rename(temporary_serial_file, serial_file)
        os.rename(temporary_db_file, db_file)
    else:
        logging.info('No New' + db_name)
    time.sleep(sleep_timer)
