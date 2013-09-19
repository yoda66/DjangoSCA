#!/usr/bin/python

import sys, os, re
from ContentReader import ContentReader
from SettingsCheck import SettingsCheck
from FormsCheck import FormsCheck

class DjangoTemplateCheck(ContentReader):

  def __init__(self,name):
    try: ContentReader.__init__(self,name)
    except: raise
    self.name = name
    if self.is_template():
      self.scan()

  def is_template(self):
    if len(self.grep('{%|%}|{{|}}')) > 0: return True
    return False

  def scan(self):
    self.run_check('.+\|safe.+','{ |safe } variable')
    self.run_check('.+autoescape\s{1,}off.+','{% autoescape off %}')


class DjangoFileCheck(ContentReader):

  def __init__(self,name):
    try: ContentReader.__init__(self,name)
    except: raise
    self.name = name
    self.scan()

  def scan(self):
    self.run_check('^@csrf_exempt$|.+csrf_exempt\s{1,}=\s{1,}True.+','csrf_exempt')
    self.run_check('.+subprocess\.(call|check).+','subprocess.call or subprocess.check*')
    self.run_check('.+os\.system.+','os.system')
    self.run_check('.+mark_safe.+','mark_safe')
    self.run_check('.+cPickle|Pickle.+','cPickle or Pickle in use')

if len(sys.argv) < 2:
  print 'usage: %s <django project dir>' % (sys.argv[0])
  print 'Author: Joff Thyer (c) 2013'
  sys.exit(1)

projdir = sys.argv[1]
if not os.path.exists(projdir):
  print 'project directory does not exist'
  sys.exit(1)

print """
[*] STAGE 1: Project Settings Tests
[*] ===============================
"""
try: SettingsCheck(projdir+'/settings.py')
except: pass

print """
[*] STAGE 2: Iterating through ALL directories and files looking for problems
[*]          .... Warning - This may take some time ....
"""
for root, dirs, files in os.walk(projdir):
  for f in files:
    fullpath = root + '/' + f
    if re.match(r'^[a-zA-Z0-9]{1}.+\.(html|txt)$',f):
      try: DjangoTemplateCheck(fullpath)
      except: pass
    elif re.match(r'^[a-zA-Z0-9]+.+$',f) and not re.match(r'.+\.pyc',f):
      try: DjangoFileCheck(fullpath)
      except: pass
      try: FormsCheck(fullpath)
      except: pass



