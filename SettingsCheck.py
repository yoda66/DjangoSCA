#!/usr/bin/python

import tempfile
import shutil
import os
import sys
import re
from django.conf import settings

class SettingsCheck(object):

  def __init__(self,name):
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

    self.required_fields = {
      'ADMINS', 'ALLOWED_HOSTS',
      'DEBUG', 'INSTALLED_APPS',
      'MANAGERS', 'MIDDLEWARE_CLASSES',
      'PASSWORD_HASHERS',
      'TEMPLATE_DEBUG',
    }

    self.specialvars = {
	'DEBUG' : False,
	'SESSION_COOKIE_SECURE' : True,
	'SESSION_COOKIE_HTTP_ONLY' : True,
	'TEMPLATE_DEBUG' : False,
    }

    self.middleware_shoulduse = {
        'django.contrib.sessions.middleware.SessionMiddleware',
        'django.middleware.csrf.CsrfViewMiddleware',
    }

    self.installed_apps_recommended = {
        'django_bleach': 'https://github.com/jsocol/bleach',
    }
    self.scan()

  def __del__(self):
    try:
      shutil.rmtree(self.tempdir)
    except:
      pass

  def requiredvars_check(self):
    #dset = dir(settings)
    for field in self.required_fields:
      try:
        value = getattr(settings, field)
        if not value: print '[*] Required field [%s] has no value set.' % (field)
      except: pass

  def middleware_check(self):
    output = ''
    middleware = []
    for m in settings.MIDDLEWARE_CLASSES:
      middleware.append(m)
      if not m.startswith('django'):
        output += '  [-] '+m+'\n'
    if len(output)>0:
      print '[*] Custom MIDDLEWARE_CLASSES:'
      print output,

    output = ''
    for ms in self.middleware_shoulduse:
      if ms not in middleware:
        output += '  [-] WARNING: consider using "'+ms+'"\n'
    if len(output)>0:
      print '[*] Recommended MIDDLEWARE_CLASSES:'
      print output,

  def specialvars_check(self):
    for v in self.specialvars:
      try:
        value = getattr(settings,v)
        if value != self.specialvars[v]:
          print '[*] WARNING: settings.%s = %s' % (v,value)
      except:
        pass

  def passwordhasher_check(self):
    ph = getattr(settings,'PASSWORD_HASHERS')
    if not re.match(r'.+\.(PBKDF2|Brcrypt).+',ph[0]):
      print '[*] WARNING: PASSWORD_HASHERS should list PBKDF2 or Bcrypt first!'

  def installed_apps_check(self):
    for app in self.installed_apps_recommended:
      try:
        if app not in getattr(settings,'INSTALLED_APPS'):
          print '[*] Consider using the installed app "%s" (%s)' \
		% (app,self.installed_apps_recommended[app])
      except:
        pass


  def scan(self):
    self.requiredvars_check()
    self.specialvars_check()
    self.passwordhasher_check()
    self.middleware_check()
    self.installed_apps_check()

