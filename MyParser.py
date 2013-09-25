#!/usr/bin/env python

import re
import ast
import csv
import xml.etree.ElementTree as ET

class MyParser(ast.NodeVisitor):

  def __init__(self,rulesfile):
    self.debug = False

    self.classes = []
    self.functions = []
    self.warnings = []
    self.rxp = re.compile(r'<(.+) object at (.+)>')

    # dictionaries for rules checking
    self.b_imports = {}
    self.b_from_imports = {}
    self.b_strings = {}
    self.b_general = {}
    self.b_template = {}

    try:
      self.__load_rules(rulesfile)
    except:
      raise


  def ast_parse(self,shortname,code):
    node = ast.parse(code)
    self.shortname = shortname
    self.visit(node)


  def nonast_parse(self,projdir,shortname,code):
    self.shortname = shortname
    self.content = code
    try: self.__rxp_nonast_check(self.b_general,self.b_general_re)
    except: raise
    if self.__istemplate():
      try: self.__rxp_nonast_check(self.b_template,self.b_template_re)
      except: raise
    elif re.match(r'.*/crossdomain\.xml',shortname):
      try: self.__crossdomain_xml(projdir+'/'+shortname)
      except: raise


  def print_warnings(self):
    for w in self.warnings:
      print '%s' % (w)


  def __load_rules(self,rulesfile):
    try:
      f = open(rulesfile, 'r')
    except:
      print '__load_rules(): failed to open rules file'
      raise
    for row in csv.reader(f,delimiter=',',quotechar='"'):
      if len(row) == 0 or re.match(r'^#.+',row[0]): continue
      if row[0] == 'import':
        self.b_imports[row[1]] = row[2]
      #elif row[0] == 'from_import':
      #  self.b_from_imports[row[1]] = (row[2], row[3])
      elif row[0] == 'string':
        self.b_strings[row[1]] = row[2]
      elif row[0] == 'general':
        self.b_general[row[1]] = row[2]
      elif row[0] == 'template':
        self.b_template[row[1]] = row[2]

    try:
      self.b_imports_re = [re.compile(r) for r in self.b_imports]
    except re.error as e:
      print '__load_rules(): regex compiled failed for [%s] [%s]' % (r,e)
      raise
    try:
      self.b_strings_re = [re.compile(r) for r in self.b_strings]
    except re.error as e:
      print '__load_rules(): regex compiled failed for [%s] [%s]' % (r,e)
      raise
    try:
      self.b_general_re = [re.compile(r) for r in self.b_general]
    except re.error as e:
      print '__load_rules(): regex compiled failed for [%s] [%s]' % (r,e)
      raise
    try:
      self.b_template_re = [re.compile(r) for r in self.b_template]
    except re.error as e:
      print '__load_rules(): regex compiled failed for [%s] [%s]' % (r,e)
      raise


  def __crossdomain_xml(self,filename):
    tree = ET.parse(filename)
    troot = tree.getroot()
    site_control = troot.find('site-control').attrib['permitted-cross-domain-policies']
    if site_control == 'master-only':
      self.warnings.append('L____: %s: crossdomain "master-only" site control enabled' % (self.shortname))
    elif site_control == 'by-ftp-filename':
      self.warnings.append('L____: %s: URLS ending in crossdomain.xml can serve up cross domain policy' % (self.shortname))
    elif site_control == 'by-content-type':
      self.warnings.append('L____: %s: Files with text/x-cross-domain-policy header can serve up cross domain policy' % (self.shortname))

    for access in troot.findall('allow-access-from'):
      if re.match(r'^\*',access.attrib['domain']):
        self.warnings.append('L____: %s: Wildcard character in domain attrib [%s]' % (self.shortname,access.attrib['domain']))
      if re.match(r'false',access.attrib['secure'],re.IGNORECASE):
        self.warnings.append('L____: %s: Non-secure protocol access for domain [%s]' % (self.shortname,access.attrib['domain']))



  def __rxp_ast_check(self,mstr,node,sset,rset):
    for (p,v) in zip(rset,sset):
      try:
        if p.match(mstr):
          try:
            self.warnings.append('L%04d: %s: %s' % \
		(node.lineno,self.shortname,sset[v]))
          except:
            self.warnings.append('L%04d: %s: %s' % \
		(-99,self.shortname,sset[v]))
      except:
        print 'rxp_ast_check(): %s' % (re.error)
        raise

  def __istemplate(self):
    if len(self.__grep('{%|%}|{{|}}')) > 0: return True
    return False

  def __grep(self,exp):
    if not self.content: return []
    i = 0
    mline = []
    rxp = re.compile(exp)
    for line in self.content.split('\n'):
      if rxp.match(line):
        mline.append(i)
      i += 1
    return mline

  def __rxp_nonast_check(self,sset,rset):
    for (p,v) in zip(rset,sset):
      for lineno in self.__grep(v):
        try: self.warnings.append('L%04d: %s: %s' % \
		(lineno,self.shortname,sset[v]))
        except: pass

  def visit_Import(self,node):
    for module in node.names:
      if self.debug: print 'visit_Import(): %s (%d)' % (module.name,node.lineno)
      try: 
        self.__rxp_ast_check(module.name,node,self.b_imports,self.b_imports_re)
      except: pass
    self.generic_visit(node)

  def visit_ImportFrom(self,node):
    if self.debug: print 'visit_ImportFrom(): %s' % node.module
    try: 
      self.__rxp_ast_check(node.module,node,self.b_imports,self.b_imports_re)
    except: pass
    #for name in node.names:
    #  if self.debug: print 'visit_ImportFrom(): %s, %s' % (node.module, name)
    #  try: 
    #    self.__rxp_ast_check(name.name,node,self.b_imports,self.b_imports_re)
    #  except: pass
    self.generic_visit(node)

  def visit_ClassDef(self,node):
    self.classes.append('%s:%d,%d' % (node.name, node.lineno, node.col_offset))
    self.generic_visit(node)

  def visit_FunctionDef(self,node):
    if self.debug: print 'visit_FunctionDef(): %s' % (node.name)
    self.functions.append('%s:%d,%d' % (node.name, node.lineno, node.col_offset))
    try: self.__rxp_ast_check(node.name,node,self.b_general,self.b_general_re)
    except: pass
    self.generic_visit(node)

#  def visit_Assign(self,node):
#    print 'assign(): %s = %s' % \
#	(str(node.targets[0]),str(node.value))
#    self.generic_visit(node)

  def visit_Str(self,node):
    if self.debug: print 'visit_Str(): %s' % (str(node.s))
    try: self.__rxp_ast_check(str(getattr(node,'s')),node,self.b_strings,self.b_strings_re)
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

