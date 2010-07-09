#!/usr/bin/python
# -*- coding: utf-8 -*-
# Original Idea :
# =>  http://code.google.com/p/pywhois/source/browse/trunk/pywhois/parser.py

import re
from whois_parsers import *

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

ripe = {}
ripe.update(mnt_by) 
ripe.update(mnt_lower)
ripe.update(mnt_routes) 
ripe.update(mnt_ref) 
ripe.update(mntners) 
ripe.update(mnt_irt) 
ripe.update(tech_c) 
ripe.update(admin_c) 
ripe.update(author)
ripe.update(zone_c)
ripe.update(persons) 
ripe.update(inum)
ripe.update(i6num)
ripe.update(origin)
ripe.update(members)
ripe.update(local_as)
ripe.update(aut_nums)
ripe.update(org)
ripe.update(form)
