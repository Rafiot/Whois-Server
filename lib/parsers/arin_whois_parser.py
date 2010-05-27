#!/usr/bin/python
# -*- coding: utf-8 -*-
# Original Idea :
# =>  http://code.google.com/p/pywhois/source/browse/trunk/pywhois/parser.py

import re

# Dict entries 
pochandles  = { 'pochandles' : '(?:TechHandle|AbuseHandle|NOCHandle|OrgTechHandle|OrgAbuseHandle|OrgNOCHandle|OrgAdminHandle):[ ]*(.*)' }
orgid       = { 'orgid'      : 'OrgID:[ ]*(.*)' }
parent      = { 'parent'     : 'Parent:[ ]*(.*)' }
netrange    = { 'netrange'   : 'NetRange:[ ]*(.*) - (.*)' }

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

    def __init__(self, text, server):
        self.text = text
        self.server = server
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
