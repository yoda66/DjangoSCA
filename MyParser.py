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
    self.obj_load = {}
    self.obj_store = {}
    self.rxpobj = re.compile(r'<(.+) object at (.+)>')

    # dictionaries for rules checking
    self.b_imports = {}
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
    self.__django_clean_validator_check()


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


  def __django_clean_validator_check(self):
    return
    for l in self.obj_store:
      print 'clean_val(): %s (%s)' % (l,self.obj_store[l])
#      print 'store(): '+clean
#    for f in self.functions:
#      print 'func(): '+f


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
      elif row[0] == 'string':
        self.b_strings[row[1]] = row[2]
      elif row[0] == 'general':
        self.b_general[row[1]] = row[2]
      elif row[0] == 'template':
        self.b_template[row[1]] = row[2]

    try: self.b_imports_re = self.__regex_compile(self.b_imports)
    except: raise
    try: self.b_strings_re = self.__regex_compile(self.b_strings)
    except: raise
    try: self.b_general_re = self.__regex_compile(self.b_general)
    except: raise
    try: self.b_template_re = self.__regex_compile(self.b_template)
    except: raise


  def __regex_compile(self,rule_dict):
    try:
      re_dict = [re.compile(r) for r in rule_dict]
    except re.error as e:
      print '__load_rules(): regex compiled failed for [%s] [%s]' % (r,e)
      raise
    return re_dict


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
    #if self.debug: print 'visit_Import(): %s (%d)' % (node.names[0].name,node.lineno)
    for alias in node.names:
      codeline = 'import '+getattr(alias,'name')
      try: self.__rxp_ast_check(codeline,node,self.b_imports,self.b_imports_re)
      except: pass
    self.generic_visit(node)


  def visit_ImportFrom(self,node):
    #if self.debug: print 'visit_ImportFrom(): %s' % (node.names[0])
    modulename = node.module
    for alias in node.names:
      codeline = 'from %s import %s' % (modulename,getattr(alias,'name'))
      try: self.__rxp_ast_check(codeline,node,self.b_imports,self.b_imports_re)
      except: pass
    self.generic_visit(node)


  def visit_ClassDef(self,node):
    self.classes.append('%s:%d,%d' % (node.name, node.lineno, node.col_offset))
    self.generic_visit(node)


  def visit_FunctionDef(self,node):
    self.functions.append(node.name)
    for statement in node.body: 
      if self.rxpobj.match(str(statement)).group(1) == '_ast.Assign':
        for target in statement.targets:
          targetname = getattr(target,'id')
          if self.rxpobj.match(str(statement.value)).group(1) == '_ast.Call':
            rhs_func = getattr(getattr(statement.value,'func'),'value')
            rhs_funcname = ''
            if self.rxpobj.match(str(rhs_func)).group(1) == '_ast.Attribute':
              rhs_funcname = getattr(rhs_func.value,'id')
            else:
              rhs_funcname = getattr(rhs_func,'id')

            attr = self.__process_attr(getattr(statement.value,'func'))
            if self.debug: print 'func(): (%s) %s = %s.%s' % \
		(node.name,targetname,rhs_funcname,attr)
#    try: self.__rxp_ast_check(node.name,node,self.b_general,self.b_general_re)
#    except: pass
    self.generic_visit(node)


  def __process_attr(self,node):
    m = self.rxpobj.match(str(node))
    retval = ''
    if m.group(1) == '_ast.Name':
      retval = getattr(node,'id')
    elif m.group(1) == '_ast.Attribute':
      retval += '#' + self.__process_attr(node.value)
    if self.debug: print 'attr(): %s' % retval
    return retval

  def visit_Str(self,node):
    #if self.debug: print 'visit_Str(): %s' % (str(node.s))
    try: self.__rxp_ast_check(str(getattr(node,'s')),node,self.b_strings,self.b_strings_re)
    except: pass
    self.generic_visit(node)


#  def visit_Assign(self,node):
#    m = self.rxpobj.match(str(node.value))
#    if m.group(1) == '_ast.Call':
#      lhs_node = getattr(node,'targets')[0]
#      rhs_node = getattr(getattr(node.value,'func'),'value')
#      temp = getattr(getattr(node.value,'func'),'ctx')
#      lhs_m = self.rxpobj.match(str(lhs_node))
#      rhs_m = self.rxpobj.match(str(rhs_node))
#      if lhs_m.group(1) == '_ast.Name' and rhs_m.group(1) == '_ast.Name':
#        print 'Assign(): %s (%s) = %s (%s) (%s)' % ( \
#		getattr(lhs_node,'id'), lhs_m.group(2), \
#		getattr(rhs_node,'id'), rhs_m.group(2), str(temp) )
#    self.generic_visit(node)


  def visit_Name(self,node):
    m = self.rxpobj.match(str(getattr(node,'ctx')))
    val = str(getattr(node,'id'))
    if m.group(1) == '_ast.Store':
      self.obj_store[val] = m.group(2)
    elif m.group(1) == '_ast.Load':
      self.obj_load[val] = m.group(2)
    self.generic_visit(node)

