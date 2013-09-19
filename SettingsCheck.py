#!/usr/bin/python

import tempfile
import shutil
import os
import sys
from django.conf import settings

class SettingsCheck(object):

  def __init__(self,name):
    self.name = name
    os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'
    if not os.path.isfile(name):
      raise
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
      'DEBUG', 'TEMPLATE_DEBUG', 'INSTALLED_APPS',
      'MANAGERS', 'ADMINS', 'MIDDLEWARE_CLASSES', 'ALLOWED_HOSTS'
    }

    self.specialvars = {
	'DEBUG' : False,
	'SESSION_COOKIE_SECURE' : True,
	'SESSION_COOKIE_HTTP_ONLY' : True,
	'TEMPLATE_DEBUG' : False,
    }
    self.scan()

  def __del__(self):
    try:
      sys.path.remove(self.tempdir)
      shutil.rmtree(self.tempdir)
    except:
      raise

  def required(self):
    #dset = dir(settings)
    for field in self.required_fields:
      try:
        value = getattr(settings, field)
        if not value: print '[*] Required field [%s] has no value set.' % (field)
      except: pass

  def middleware_check(self):
    print '[*] MIDDLEWARE_CLASSES'
    for m in settings.MIDDLEWARE_CLASSES:
      print '  [-] '+m

  def specialvars_check(self):
    for v in self.specialvars:
      try:
        value = getattr(settings,v)
        if value != self.specialvars[v]:
          print '[*] WARNING: settings.%s = %s' % (v,value)
      except:
        pass


  def scan(self):
    self.required()
    self.middleware_check()
    self.specialvars_check()

