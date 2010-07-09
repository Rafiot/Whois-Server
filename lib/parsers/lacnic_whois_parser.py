#!/usr/bin/python
# -*- coding: utf-8 -*-
# Original Idea :
# =>  http://code.google.com/p/pywhois/source/browse/trunk/pywhois/parser.py

import re
from whois_parsers import *

# Dict entries 
tech_c      = { 'tech_c'    : '\ntech-c' + regex_ending }       # person
admin_c     = { 'admin_c'   : '\nadmin-c' + regex_ending }      # person
zone_c      = { 'zone_c'    : '\nzone-c' + regex_ending }       # person
persons     = { 'persons'   : '\n(?:tech-c|admin-c|zone-c)' + regex_ending }

inum        = { 'inetnum'   : '^inetnum' + regex_ending }
parent      = { 'parent'    : '^inetnum-up' + regex_ending }

lacnic = {}
lacnic.update(tech_c) 
lacnic.update(admin_c) 
lacnic.update(zone_c)
lacnic.update(persons) 
lacnic.update(inum)
lacnic.update(parent)
