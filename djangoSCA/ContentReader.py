#!/usr/bin/env python

import re
import os


class ContentReader(object):

    """
    This class is designed to read in file content, and save it to
    a variable named "self.content".  The original project name file
    path will be kept as well as a derived relative shortname path.
    Other classes needing file content will use this as a base class.
    """

    def __init__(self, projdir, name):
        self.name = name
        self.projdir = projdir
        self.shortname = self.name[len(self.projdir):]
        if re.match(r'^/.+', self.shortname):
            self.shortname = self.shortname[1:]
        try:
            self.content = self.getfile()
        except:
            raise

    def getfile(self):
        try:
            f = open(self.name, 'r')
        except:
            raise IOError
        content = ''
        for line in f.readlines():
            content += line
        f.close()
        return content
