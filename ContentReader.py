#!/usr/bin/env python

import re
import os

class ContentReader(object):

  def __init__(self,projdir,name):
    self.name = name
    self.projdir = projdir
    self.shortname = self.name[len(self.projdir):]
    try: self.content = self.getfile()
    except: raise Exception('ContentReader Error')

  def getfile(self):
    try: f = open(self.name,'r')
    except: raise IOError
    content = ''
    for line in f.readlines():
      content += line
    f.close()
    return content

  def grep(self,exp):
    if not self.content: return []
    i = 0
    mline = []
    rxp = re.compile(exp)
    for line in self.content.split('\n'):
      if rxp.match(line):
        mline.append(i)
      i += 1
    return mline

  def run_check(self,exp,msg):
    res = self.grep(exp)
    if len(res) > 0:
      print '[*] %s: %s LINE#%s' % (self.shortname,msg,str(res))

