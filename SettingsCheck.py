#!/usr/bin/python

from ContentReader import ContentReader

class SettingsCheck(ContentReader):

  def __init__(self,name):
    try: ContentReader.__init__(self,name)
    except: raise
    self.REQUIRED_FIELDS = {
      'DEBUG': bool,
      'TEMPLATE_DEBUG': bool,
      'INSTALLED_APPS': tuple,
      'MANAGERS': tuple,
      'ADMINS': tuple,
      'MIDDLEWARE_CLASSES': tuple,
    }
    self.scan()

  def required_fields(self):
    for field, req_type in self.REQUIRED_FIELDS.iteritems():
      if len(self.grep(field)) == 0:
	print '[*] "' + field + '" is REQUIRED'
 
  def scan(self):
    self.required_fields()
    if self.grep('DEBUG\s{1,}=\s{1,}True'): print '[*] WARNING: DEBUG mode enabled'

