#!/usr/bin/python
# -*- coding: utf-8 -*-
# Original Idea :
# =>  http://code.google.com/p/pywhois/source/browse/trunk/pywhois/parser.py

import re
from whois_parsers import *

# Dict entries 
TechHandle      = { 'TechHandle'        : '\nTechHandle' + regex_ending }
AbuseHandle     = { 'AbuseHandle'       : '\nAbuseHandle' + regex_ending }
NOCHandle       = { 'NOCHandle'         : '\nNOCHandle' + regex_ending }
OrgTechHandle   = { 'OrgTechHandle'     : '\nOrgTechHandle' + regex_ending }
OrgAbuseHandle  = { 'OrgAbuseHandle'    : '\nOrgAbuseHandle' + regex_ending }
OrgNOCHandle    = { 'OrgNOCHandle'      : '\nOrgNOCHandle' + regex_ending }
OrgAdminHandle  = { 'OrgAdminHandle'    : '\nOrgAdminHandle' + regex_ending }
pochandles      = { 'pochandles'        : '\n(?:TechHandle|AbuseHandle|NOCHandle|OrgTechHandle|OrgAbuseHandle|OrgNOCHandle|OrgAdminHandle)' + regex_ending }


orgid       = { 'orgid'      : '\nOrgID' + regex_ending }
parent      = { 'parent'     : '\nParent' + regex_ending }
netrange    = { 'netrange'   : '\nNetRange:[ ]*(.*) - (.*)' }


arin = {}
arin.update(orgid)
arin.update(parent)
arin.update(netrange)
arin.update(pochandles)
