#!/usr/bin/python

import re
from ContentReader import ContentReader

class FormsCheck(ContentReader):

  def __init__(self,name):
    try: ContentReader.__init__(self,name)
    except: raise
    self.name = name
    if self.is_form():
      print self.class_names()

  def is_form(self):
    if self.grep('^from django import forms$'):
      return True
    return False

  def class_names(self):
    clnames = []
    regex = re.compile('^class\s{1,}(.+)\(.+$')
    for line in self.content.split('\n'):
      match = regex.match(line)
      if match:
        clnames.append(match.group(1))
    return clnames
 

