#!/usr/bin/env python

import sys, os, re
import datetime
from ContentReader import ContentReader
from SettingsCheck import SettingsCheck
from MyParser import MyParser


class DjangoTemplateCheck(ContentReader):

  def __init__(self,projdir,name):
    try: ContentReader.__init__(self,projdir,name)
    except: raise
    self.name = name
    if self.is_template():
      self.scan()

  def is_template(self):
    if len(self.grep('{%|%}|{{|}}')) > 0: return True
    return False

  def parseme(self):
#    parser = MyParser()
#    parser.nonast_parse(self.shortname,self.content)
#    parser.print_warnings()

    self.run_check('.+\|safe.+','%OWASP-CR-APIUsage: { |safe } variable')
    self.run_check('.+autoescape\s{1,}off.+','%OWASP-CR-APIUsage: {% autoescape off %}')


class DjangoFileCheck(ContentReader):

  def __init__(self,projdir,name):
    try: ContentReader.__init__(self,projdir,name)
    except: raise
    self.name = name
    self.parseme()

  def parseme(self):
    parser = MyParser()
    parser.parse(self.shortname,self.content)
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
""" % (projdir,datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
try: SettingsCheck(projdir+'/settings.py')
except: pass

print """
[*]---------------------------------------------
[*] STAGE 2: Testing ALL directories and files
[*] .... Warning - This may take some time ....
[*]---------------------------------------------
"""
for root, dirs, files in os.walk(projdir):
  for f in files:
    fullpath = root + '/' + f
    if re.match(r'^[a-zA-Z0-9]{1}.+\.(html|txt)$',f):
      try: DjangoTemplateCheck(projdir,fullpath)
      except: pass
    if re.match(r'^[a-zA-Z0-9]+.+\.py$',f):
      try: DjangoFileCheck(projdir,fullpath)
      except: pass
