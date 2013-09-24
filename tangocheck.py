#!/usr/bin/env python

import sys, os, re
import datetime
import ast
from ContentReader import ContentReader
from SettingsCheck import SettingsCheck
from FormsCheck import FormsCheck


class MyParser(ast.NodeVisitor):

  def __init__(self):
    self.debug = False
    self.rxp = re.compile(r'<(.+) object at (.+)>')
    self.classes = []
    self.functions = []
    self.warnings = []

    self.b_import = {
      '.*(Pickle|cPickle).*':
	'%OWASP-CR-APIUsage: cPickle or Pickle in use',
    }
    try: self.b_import_re = [re.compile(r) for r in self.b_import]
    except: raise

    self.b_func = {
      '.*subprocess\.(call|check).*':
	'%OWASP-CR-ResourceUsage: subprocess.call or subprocess.check*',
      '.*os\.system\(.+\).*':
	'%OWASP-CR-ResourceUsage: os.system',
      '.*random\.random\(\).*':
	'%OWASP-CR-ResourceUsage: random.random() pseudo-random number generator in use',
    }
    try: self.b_func_re = [re.compile(r) for r in self.b_func]
    except: raise

    self.b_str = {
      '.*(SELECT|select).+(FROM|from).+(WHERE|where).*':
		'%OWASP-CR-APIUsage: SQL SELECT query found in source',
      '.*(INSERT|insert)\s{1,}(INTO|into).+(VALUES|values)\s{1,}\(.+\).*':
		'%OWASP-CR-APIUsage: SQL INSERT query found in source',
      '.*(DELETE|delete)\s{1,}(FROM|from).+(WHERE|where).*':
		'%OWASP-CR-APIUsage: SQL DELETE query found in source',
      '.*joff.*':
		'%OWASP-CR-APIUsage: JOFF found in source',
    }
    try: self.b_str_re = [re.compile(r) for r in self.b_str]
    except: raise


  def parse(self,shortname,code):
    node = ast.parse(code)
    self.shortname = shortname
    self.visit(node)

  def rxp_check(self,mstr,node,sset,rset):
    for (p,v) in zip(rset,sset):
      try:
        if p.match(mstr):
          try:
            self.warnings.append('L%03d,C%03d: %s: %s' % \
		(node.lineno,node.col_offset,self.shortname,sset[v]))
          except:
            self.warnings.append('L%03d,C%03d: %s: %s' % \
		(-99,-99,self.shortname,sset[v]))
      except:
        print 'rxp_check(): %s' % (re.error)
        raise

  def print_warnings(self):
    for w in self.warnings:
      print '%s' % (w)

  def visit_Import(self,node):
    if self.debug: print 'visit_Import(): %s (%d)' % (node.names[0].name,node.lineno)
    try: self.rxp_check(node.names[0].name,node,self.b_import,self.b_import_re)
    except: pass
    self.generic_visit(node)

  def visit_ImportFrom(self,node):
    if self.debug: print 'visit_ImportFrom(): %s' % (node.names[0])
    self.generic_visit(node)

#  def visit_alias(self,node):
#    try: self.rxp_check(node.name,node,self.b_import,self.b_import_re)
#    except: pass
#    self.generic_visit(node)

  def visit_ClassDef(self,node):
    self.classes.append('%s:%d,%d' % (node.name, node.lineno, node.col_offset))
    self.generic_visit(node)

  def visit_FunctionDef(self,node):
    if self.debug: print 'visit_FunctionDef(): %s' % (node.name)
    self.functions.append('%s:%d,%d' % (node.name, node.lineno, node.col_offset))
    try: self.rxp_check(node.name,node,self.b_func,self.b_func_re)
    except: pass
    self.generic_visit(node)

  def visit_Assign(self,node):
#    print 'assign(): %s = %s' % \
#	(str(node.targets[0]),str(node.value))
    self.generic_visit(node)

  def visit_Str(self,node):
    if self.debug: print 'visit_Str(): %s' % (str(node.s))
    try: self.rxp_check(str(getattr(node,'s')),node,self.b_str,self.b_str_re)
    except: pass
    self.generic_visit(node)

#  def visit_Tuple(self,node):
#    for c in ast.iter_fields(node.elts):
#      print 'tuple(): %s' % (str(c))
#    self.generic_visit(node)

#  def visit_Name(self,node):
#    for c in ast.iter_fields(node):
#      print 'name(): %s' % (str(c))
#    self.generic_visit(node)

#  def visit_Call(self,node):
#    for c in ast.iter_fields(node.func.value):
#      print 'call(): %s' % (str(c))
#    self.generic_visit(node)


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

  def scan(self):
    self.run_check('.+\|safe.+','%OWASP-CR-APIUsage: { |safe } variable')
    self.run_check('.+autoescape\s{1,}off.+','%OWASP-CR-APIUsage: {% autoescape off %}')


class DjangoFileCheck(ContentReader):

  def __init__(self,projdir,name):
    try: ContentReader.__init__(self,projdir,name)
    except: raise
    self.name = name
    #self.scan()
    self.parseme()

#  def scan(self):
#    self.run_check('^@csrf_exempt$|.+csrf_exempt\s{1,}=\s{1,}True.+','%OWASP-CR-InputValidation: csrf_exempt')
#    self.run_check('.*subprocess\.(call|check).*','%OWASP-CR-ResourceUsage: subprocess.call or subprocess.check*')
#    self.run_check('.*os\.system\(.+\).*','%OWASP-CR-ResourceUsage: os.system')
#    self.run_check('.*mark_safe.*','%OWASP-CR-APIUsage: mark_safe')
#    self.run_check('.*cPickle|Pickle.*','%OWASP-CR-APIUsage: cPickle or Pickle in use')
#    self.run_check('.*random\.random\(\).*','%OWASP-CR-ResourceUsage: random.random() pseudo-random number generator in use')
#    self.run_check('.*(SELECT|select).+(FROM|from).+(WHERE|where).*','%OWASP-CR-APIUsage: SQL SELECT query found in source')
#    self.run_check('.*(INSERT|insert)\s{1,}(INTO|into).+(VALUES|values)\s{1,}\(.+\).*','%OWASP-CR-APIUsage: SQL INSERT query found in source')
#    self.run_check('.*(DELETE|delete)\s{1,}(FROM|from).+(WHERE|where).*','%OWASP-CR-APIUsage: SQL DELETE query found in source')

  def parseme(self):
    parser = MyParser()
    parser.parse(self.shortname,self.content)
    parser.print_warnings()

if len(sys.argv) < 2:
  print 'usage: %s <django project dir>' % (sys.argv[0])
  print 'Author: Joff Thyer (c) 2013'
  sys.exit(1)

projdir = sys.argv[1]
if not os.path.exists(projdir):
  print 'project directory does not exist'
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
#    if re.match(r'^[a-zA-Z0-9]{1}.+\.(html|txt)$',f):
#      try: DjangoTemplateCheck(projdir,fullpath)
#      except: pass
    if re.match(r'^[a-zA-Z0-9]+.+\.py$',f):
      try: DjangoFileCheck(projdir,fullpath)
      except: pass
#      try: FormsCheck(fullpath)
#      except: pass



