#!/usr/bin/env python

import re
import os

class ContentReader(object):

  def __init__(self,projdir,name):
    self.name = name
    self.projdir = projdir
    self.shortname = self.name[len(self.projdir):]
    if re.match(r'^/.+',self.shortname):
      self.shortname = self.shortname[1:]

    try:
      self.content = self.getfile()
    except:
      raise

  def getfile(self):
    try:
      f = open(self.name,'r')
    except:
      raise IOError
    content = ''
    for line in f.readlines():
      content += line
    f.close()
    return content


