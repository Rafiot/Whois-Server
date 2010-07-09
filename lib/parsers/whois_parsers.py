import re

regex_ending = ':[\s]*([^{#\n]*)'

class AbstractParser(object):
    """Abstract Class for parsing a Whois entry.
    """
    def __init__(self, text, origin):
        self.text = text
        self._whois_regs = self.possible_regex.get(origin, {})

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
                    setattr(self, attr, value[0])
                return getattr(self, attr)
            else:
                raise KeyError("Unknown attribute: %s" % attr)
    
    def __repr__(self):
        return self.text
