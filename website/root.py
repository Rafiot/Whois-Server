#!/usr/bin/env python

import os
import cherrypy
from Cheetah.Template import Template


APPDIR = os.path.dirname(os.path.abspath(__file__))
INI_FILENAME = os.path.join(APPDIR, "config/cptest.ini")

config = ConfigParser.RawConfigParser()
config.read("../etc/whois-server.conf")

sys.path.append(os.path.join(root_dir,config.get('global','lib')))

redis_db = config.get('whois_server','redis_db')

class Root(object):

#    def index(self):
#        filename = os.path.join(APPDIR, "index.tmpl")
#        template = Template(file = filename)
#
#        template.title = "Die Indexseite (CherryPy)"
#        template.content = (
#            "Dieser Text befindet sich auf der Indexseite.\n"
#            "Dieser Text wurde von CherryPy ersetzt."
#        )
#       return str(template)
    def index(self, query = ""):
#        if vorname:
#            template = Template("Dein Vorname ist $vorname.")
#            template.vorname = vorname
#            return str(template)
#        else:
#            return \
#                """
#                Es wurde kein Vorname uebergeben.
#                <a href="/?vorname=Thomas">Mit Vorname
#                sieht das so aus...</a>
#                """
        if query:
            template = Template("Your last query is $vorname.")
            template.query = query
            return str(template)
        else:
            return \
                """
                Please send a query
                <form method="POST" action=".">
                  <input type="text" name="vorname" value="Thomas">
                  <input type="submit" value="Submit">
                </form>
                """

    index.exposed = True
    
    def myfunction(self):
        return "Es wurde die neue Funktion aufgerufen"
    myfunction.exposed = True

class MySubdir(object):

    def index(self):
        return 'Indexseite des "virtuellen" Ordners "mysubdir".'
    index.exposed = True


    def afunction(self):
        return "Es wurde die Methode 'afunction' der MySubdir-Klasse aufgerufen."
    afunction.exposed = True


# put all together 
root = Root()
root.mysubdir = MySubdir()


def main():
    cherrypy.quickstart(Root(), config = INI_FILENAME)


if __name__ == "__main__":
    main()
