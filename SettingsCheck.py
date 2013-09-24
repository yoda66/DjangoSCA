#!/usr/bin/env python

import tempfile
import shutil
import os
import sys
import re
import csv
from django.conf import settings

class SettingsCheck(object):

  def __init__(self,name,rules):
    self.name = name
    os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'
    if not os.path.isfile(name):
      raise
      return
    try:
      self.tempdir = tempfile.mkdtemp()
      sys.path.append(self.tempdir)
    except:
      raise
    try:
      shutil.copy(self.name,self.tempdir)
    except:
      raise

    self.b_apps = {}
    self.b_fields = {}
    self.b_middleware = {}
    self.b_vars = {}
    try:
      self.__load_rules(rules)
    except:
      raise
    self.scan()


  def __del__(self):
    try:
      shutil.rmtree(self.tempdir)
    except:
      pass

  def __load_rules(self,rulesfile):
    try:
      f = open(rulesfile, 'r')
    except:
      print '__load_rules(): failed to open rules file'
      raise
    for row in csv.reader(f,delimiter=',',quotechar='"'):
      if len(row) == 0 or re.match(r'^#.+',row[0]): continue
      if row[0] == 'settings_rec_apps':
        self.b_apps[row[1]] = row[2]
      elif row[0] == 'settings_req_field':
        self.b_fields[row[1]] = ''
      elif row[0] == 'settings_rec_middleware':
        self.b_middleware[row[1]] = ''
      elif row[0] == 'settings_rec_var':
        self.b_vars[row[1]] = row[2]


  def __required_fields(self):
    for field in self.b_fields:
      try:
        if not getattr(settings, field):
          print '[*] %%OWASP-CR-APIUsage: Required field [%s] has no value set.' % (field)
      except:
        print '[*] %%OWASP-CR-APIUsage: Required field [%s] does not exist.' % (field)
        pass


  def __recommended_variable_settings(self):
    for v in self.b_vars:
      try:
        value = getattr(settings,v)
        if value != self.b_vars[v]:
          print '[*] %%OWASP-CR-APIUsage: Incorrect recommended variable setting [%s = %s]' % (v,value)
      except:
        print '[*] %%OWASP-CR-APIUsage: Recommended variable [%s] does not exist.' % (v)
        pass


  def __recommended_middleware(self):
    output = ''
    middleware = []
    for m in settings.MIDDLEWARE_CLASSES:
      middleware.append(m)
      if not m.startswith('django'):
        output += '  [-] %OWASP-CR-APIUsage: '+m+'\n'
    if len(output)>0:
      print '[*] %OWASP-CR-APIUsage: Custom MIDDLEWARE_CLASSES:'
      print output,
    output = ''
    for ms in self.b_middleware:
      if ms not in middleware:
        output += '  [-] %OWASP-CR-APIUsage: consider using "'+ms+'"\n'
    if len(output)>0:
      print '[*] %OWASP-CR-APIUsage: Recommended MIDDLEWARE_CLASSES:'
      print output,


  def __recommended_apps(self):
    output = ''
    for app in self.b_apps:
      try:
        if app not in getattr(settings,'INSTALLED_APPS'):
          output += '  [-] %%OWASP-CR-APIUsage: Consider using installed app "%s" (%s)' \
		% (app,self.b_apps[app])
      except:
        output += '  [-] %%OWASP-CR-APIUsage: Recommended installed app [%s] is not configured.' % (app)
        pass
    if len(output)>0:
      print '[*] %OWASP-CR-APIUsage: Recommended INSTALLED_APPS:'
      print output,


  def __password_hashers(self):
    ph = getattr(settings,'PASSWORD_HASHERS')
    if not re.match(r'.+\.(PBKDF2|Brcrypt).+',ph[0]):
      print '[*] %OWASP-CR-APIUsage: PASSWORD_HASHERS should list PBKDF2 or Bcrypt first!'

  def scan(self):
    self.__required_fields()
    self.__recommended_variable_settings()
    self.__recommended_middleware()
    self.__recommended_apps()
    self.__password_hashers()

