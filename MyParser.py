#!/usr/bin/env python

import re
import ast

class MyParser(ast.NodeVisitor):

  def __init__(self):
    self.debug = False
    self.rxp = re.compile(r'<(.+) object at (.+)>')
    self.classes = []
    self.functions = []
    self.warnings = []

    self.b_import = {
      'Pickle': '%OWASP-CR-APIUsage: import Pickle',
      'cPickle': '%OWASP-CR-APIUsage: import cPickle',
      'mark_safe': '%OWASP-CR-APIUsage: import mark_safe',
    }
    try: self.b_import_re = [re.compile(r) for r in self.b_import]
    except: raise

    self.b_func = {
      '@csrf_exempt$|.+csrf_exempt\s{1,}=\s{1,}True.+':
	'%OWASP-CR-InputValidation: csrf_exempt',
      '.*mark_safe\(.+\).*':
	'%OWASP-CR-ResourceUsage: mark_safe() function call',
      '.*os\.system\(.+\).*':
	'%OWASP-CR-ResourceUsage: os.system() function call',
      '.*random\.random\(\).*':
	'%OWASP-CR-ResourceUsage: random.random() PRNG function call',
      '.*subprocess\.(call|check).*':
	'%OWASP-CR-ResourceUsage: subprocess.call() or subprocess.check_*() function call',
    }
    try: self.b_func_re = [re.compile(r) for r in self.b_func]
    except: raise

    self.b_str = {
      '.*(SELECT|select).+(FROM|from).+(WHERE|where).*':
		'%OWASP-CR-APIUsage: SQL SELECT query found',
      '.*(INSERT|insert)\s{1,}(INTO|into).+(VALUES|values)\s{1,}\(.+\).*':
		'%OWASP-CR-APIUsage: SQL INSERT query found',
      '.*(DELETE|delete)\s{1,}(FROM|from).+(WHERE|where).*':
		'%OWASP-CR-APIUsage: SQL DELETE query found',
    }
    try: self.b_str_re = [re.compile(r) for r in self.b_str]
    except: raise


  def parse(self,shortname,code):
    node = ast.parse(code)
    self.shortname = shortname
    self.visit(node)


  def nonast_parse(self,shortname,code):
    self.shortname = shortname
    self.content = code
    try: self.__rxp_nonast_check(self.b_func,self.b_func_re)
    except: pass


  def print_warnings(self):
    for w in self.warnings:
      print '%s' % (w)


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
    if self.debug: print 'visit_Import(): %s (%d)' % (node.names[0].name,node.lineno)
    try: self.__rxp_ast_check(node.names[0].name,node,self.b_import,self.b_import_re)
    except: pass
    self.generic_visit(node)

  def visit_ImportFrom(self,node):
    if self.debug: print 'visit_ImportFrom(): %s' % (node.names[0])
    try: self.__rxp_ast_check(node.names[0].name,node,self.b_import,self.b_import_re)
    except: pass
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
    try: self.__rxp_ast_check(node.name,node,self.b_func,self.b_func_re)
    except: pass
    self.generic_visit(node)

#  def visit_Assign(self,node):
#    print 'assign(): %s = %s' % \
#	(str(node.targets[0]),str(node.value))
#    self.generic_visit(node)

  def visit_Str(self,node):
    if self.debug: print 'visit_Str(): %s' % (str(node.s))
    try: self.__rxp_ast_check(str(getattr(node,'s')),node,self.b_str,self.b_str_re)
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

