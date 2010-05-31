#!/usr/bin/python
# -*- coding: utf-8 -*-
# Original Idea :
# =>  http://code.google.com/p/pywhois/source/browse/trunk/pywhois/parser.py

import re


regex_ending = ':[\s]*([^{#\n]*)'

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


all_possible_keys = {}
all_possible_keys.update(orgid)
all_possible_keys.update(parent)
all_possible_keys.update(netrange)
all_possible_keys.update(pochandles)

class ARINWhois():
    """
    This class return a dump of the Whois. 
    Til we have a real implementation of whois in python, 
    we will use this class to return all the informations
    """
#    possible_regex = {
#        '^OrgID:'       : OrgID, 
#        '^NetHandle:'   : NetHandle, 
#        '^V6NetHandle:' : V6NetHandle, 
#        '^ASHandle:'    : ASHandle, 
#        '^POCHandle:'   : POCHandle
#        }

    def __init__(self, text):
        self.text = text
        self._whois_regs = all_possible_keys
    
    def __getattr__(self, attr):
        """The first time an attribute is called it will be calculated here.
        The attribute is then set to be accessed directly by subsequent calls.
        """
        try: 
            return getattr(self.__class__, attr)
        except AttributeError:
            whois_reg = self._whois_regs.get(attr)
            if whois_reg:
                value = re.findall(whois_reg, self.text)
                if not value:
                    setattr(self, attr, None)
                else:
                    setattr(self, attr, value)
                return getattr(self, attr)
            else:
                raise KeyError("Unknown attribute: %s" % attr)

    def __repr__(self):
        return self.text
