#!/usr/bin/env python

import sys, os, re
import datetime
from ContentReader import ContentReader
from SettingsCheck import SettingsCheck
from MyParser import MyParser


class DjangoFileCheck(ContentReader):

  def __init__(self,projdir,filename,rulesfile):
    try:
      ContentReader.__init__(self,projdir,filename)
    except:
      raise
    self.rulesfile = rulesfile
    self.parseme()


  def parseme(self):
    try:
      parser = MyParser(self.rulesfile)
    except:
      raise
    if re.match(r'.+\.py$',self.shortname):
      parser.ast_parse(self.shortname,self.content)
    parser.nonast_parse(self.shortname,self.content)
    parser.print_warnings()


if len(sys.argv) < 2:
  print 'usage: %s <django project dir>' % (sys.argv[0])
  print 'Author: Joff Thyer (c) 2013'
  sys.exit(1)

projdir = sys.argv[1]
if not os.path.isdir(projdir):
  print 'project directory does not exist or is not a directory'
  sys.exit(1)

# set the rules file name
rulesfile = 'tangocheck.rules'

print """
___________________________________________________________

  TangoCheck Version 1.0
  Author: Joff Thyer (c) 2013
  Project Dir/Name..: %s
  Date of Test......: %s
___________________________________________________________

[*]---------------------------------
[*] STAGE 1: Project Settings Tests 
[*]---------------------------------
[*]""" % (projdir,datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
try:
  SettingsCheck(projdir+'/settings.py',rulesfile)
except:
  raise

print """
[*]---------------------------------------------
[*] STAGE 2: Testing ALL directories and files
[*] .... Warning - This may take some time ....
[*]---------------------------------------------
[*]"""
for root, dirs, files in os.walk(projdir):
  for f in files:
    fullpath = root + '/' + f
    if re.match(r'^[a-zA-Z0-9]+.+\.(py|html|txt)$',f):
      try:
        DjangoFileCheck(projdir,fullpath,rulesfile)
      except:
        raise

