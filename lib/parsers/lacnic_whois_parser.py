#!/usr/bin/python
# -*- coding: utf-8 -*-
# Original Idea :
# =>  http://code.google.com/p/pywhois/source/browse/trunk/pywhois/parser.py

import re

regex_ending = ':[\s]*([^{#\n]*)'

# Dict entries 
tech_c      = { 'tech_c'    : '\ntech-c' + regex_ending }       # person
admin_c     = { 'admin_c'   : '\nadmin-c' + regex_ending }      # person
zone_c      = { 'zone_c'    : '\nzone-c' + regex_ending }       # person
persons     = { 'persons'   : '\n(?:tech-c|admin-c|zone-c)' + regex_ending }

# Sometimes, the second IP is on the next line....
inum        = { 'inetnum'   : '^inetnum' + regex_ending }
parent      = { 'parent'    : '^inetnum-up' + regex_ending }

all_possible_keys = {}

all_possible_keys.update(tech_c) 
all_possible_keys.update(admin_c) 
all_possible_keys.update(zone_c)
all_possible_keys.update(persons) 

all_possible_keys.update(inum)
all_possible_keys.update(parent)

class LACNICWhois():
    """
    This class return a dump of the Whois. 
    Til we have a real implementation of whois in python, 
    we will use this class to return all the informations
    """

    def __init__(self, text):
        self.text = text
        self._whois_regs = all_possible_keys
    
    def __getattr__(self, attr):
        """The first time an attribute is called it will be calculated here.
        The attribute is then set to be accessed directly by subsequent calls.
        """
        to_return = getattr(self.__class__, attr, None)
        if to_return is None:
            whois_reg = self._whois_regs.get(attr, None)
            if whois_reg is not None:
                value = re.findall(whois_reg, self.text)
                if len(value) == 0 :
                    setattr(self, attr, None)
                else:
                    setattr(self, attr, value)
                to_return = getattr(self, attr)
            else:
                print("Unknown attribute: %s" % attr)
        return to_return
    
    def __repr__(self):
        return self.text
