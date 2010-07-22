import re
from whois_parsers import *
from arin_whois_parser import *
from ripe_whois_parser import *
from lacnic_whois_parser import *


class Whois(AbstractParser):
    """
    This class return a dump of the Whois. 
    Til we have a real implementation of whois in python, 
    we will use this class to return all the informations
    """
    possible_regex = {
        'whois.arin.net'   : arin, 
        'whois.ripe.net'   : ripe, 
        'whois.lacnic.net' : lacnic
        }

