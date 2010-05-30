#!/usr/bin/python
# -*- coding: utf-8 -*-
# Original Idea :
# =>  http://code.google.com/p/pywhois/source/browse/trunk/pywhois/parser.py

import re

regex_ending = ':[\s]*([^{#\n]*)'

# Dict entries 
mnt_by      = { 'mnt_by'    : '\nmnt-by' + regex_ending }       # mntner
mnt_lower   = { 'mnt_lower' : '\nmnt-lower' + regex_ending }    # mntner
mnt_routes  = { 'mnt_routes': '\nmnt-routes' + regex_ending }   # mntner
mnt_ref     = { 'mnt_ref'   : '\nmnt-ref' + regex_ending }      # mntner
mntners     = { 'mntners'   : '\n(?:mnt-by|mnt-lower|mnt-routes|mnt-ref)' + regex_ending }

mnt_irt     = { 'mnt_irt'   : '\nmnt-irt' + regex_ending }      # irt

tech_c      = { 'tech_c'    : '\ntech-c' + regex_ending }       # person
admin_c     = { 'admin_c'   : '\nadmin-c' + regex_ending }      # person
author      = { 'author'    : '\nauthor' + regex_ending }       # person
zone_c      = { 'zone_c'    : '\nzone-c' + regex_ending }       # person
persons     = { 'persons'   : '\n(?:tech-c|admin-c|author|zone-c)' + regex_ending }

nic_hdl     = { 'nic_hdl'   : '\nnic-hdl' + regex_ending }      # person

origin      = { 'origin'    : '\norigin' + regex_ending }       # aut-num

members     = { 'members'   : '\nmembers' + regex_ending }      # aut-num
local_as    = { 'local_as'  : '\nlocal-as' + regex_ending }     # aut-num
aut_nums    = { 'aut_nums'   : '\n(?:members|local-as)' + regex_ending }

# Sometimes, the second IP is on the next line....
inum        = { 'inetnum'   : '^inetnum:[\s]*(.*)[\s\n]*-[\s]*([^{#\n]*)' }
#inum        = { 'inetnum'   : '^inetnum:[\s]*(.*)[ ]*-[ ]*(.*)' ,
#                'inetnum2l' : '^inetnum:[\s]*(.*)[ \n]*-[ ]*(.*)'}
i6num       = { 'inet6num'  : '^inet6num' + regex_ending }

org         = { 'org'       : '\norg' + regex_ending }          # organisation
form        = { 'form'      : '\nform' + regex_ending }         # poetic-form

all_possible_keys = {}

all_possible_keys.update(mnt_by) 
all_possible_keys.update(mnt_lower)
all_possible_keys.update(mnt_routes) 
all_possible_keys.update(mnt_ref) 
all_possible_keys.update(mntners) 

all_possible_keys.update(mnt_irt) 

all_possible_keys.update(tech_c) 
all_possible_keys.update(admin_c) 
all_possible_keys.update(author)
all_possible_keys.update(zone_c)
all_possible_keys.update(persons) 

all_possible_keys.update(inum)
all_possible_keys.update(i6num)

all_possible_keys.update(origin)
all_possible_keys.update(members)
all_possible_keys.update(local_as)
all_possible_keys.update(aut_nums)


all_possible_keys.update(org)
all_possible_keys.update(form)

class RIPEWhois():
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
