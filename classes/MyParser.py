#!/usr/bin/env python

import re
import sys
import ast
import csv
import xml.etree.ElementTree as ET


class MyParser(ast.NodeVisitor):

    """
    This class extends the AST (Abstract Syntax Tree) python class
    in order to parse through the content of any loaded file.  If the file that
    is in need of parsing is not a python script, then this class also
    implements a basic regular expression parser to accomodate.
    All of the DjangoSCA based warnings will be appended to a list named
    self.warnings[], and can be printed with the print_warnings() method.
    All of the methods that begin with the prefix "visit_" are callback
    methods extending from AST.  As syntax is parsed, these methods will
    be called depending on what part of the grammar is being parsed.
    Methods prefixed with 'django_' are by convention intended to be
    django logic checks.
    """

    def __init__(self, rulesfile, filehandle):
        self.debug = False
        self.filehandle = filehandle
        self.imports = []
        self.classes = []
        self.func_assign = []
        self.class_func_assign = {}
        self.warnings = []
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

    def ast_parse(self, shortname, code):
        try:
            node = ast.parse(code)
        except (SyntaxError, NameError, ValueError, TypeError) as err:
            warning = \
                'L____: %s: %%OWASP-CR-SourceCodeDesign: AST parsing: %s' \
                % (shortname, err)
            self.warnings.append(warning)
            return
        self.shortname = shortname
        self.visit(node)
        self.__django_logic_checks()

    def nonast_parse(self, projdir, shortname, code):
        self.shortname = shortname
        self.content = code
        try:
            self.__rxp_nonast_check(self.b_general, self.b_general_re)
        except:
            raise
        if self.__istemplate():
            try:
                self.__rxp_nonast_check(self.b_template, self.b_template_re)
            except:
                raise
        elif re.match(r'.*crossdomain\.xml', shortname):
            try:
                self.__crossdomain_xml(projdir + '/' + shortname)
            except:
                raise

    def print_warnings(self):
        for w in self.warnings:
            self.filehandle.write('%s\n' % (w))
        return len(self.warnings)

    def __django_logic_checks(self):
        for l in self.class_func_assign:

            """
            If there is no corresponding clean_ function for a Django
            forms.Charfield(), then we might have input validation
            issues.
            """
            if re.match(r'^forms\.CharField', self.class_func_assign[l]):
                classname = l.split(':')[0]
                function_name = l.split(':')[1]
                lineno = int(l.split(':')[2])
                clean_function_name = 'clean_' + function_name
                search_name = classname + ':' + clean_function_name
                if not search_name in self.classes:
                    warning = """\
L%04d: %s: %%OWASP-CR-SourceCodeDesign: Django forms validation function [%s] does not exist for Class [%s] assignment [%s = %s]""" % (
                        lineno,
                        self.shortname,
                        clean_function_name,
                        classname,
                        function_name,
                        self.class_func_assign[l])
                    self.warnings.append(warning)

            elif re.match(r'^Meta:fields', l) \
                    and self.class_func_assign[l] == '__all__' \
                    and self.__search_imports('ModelForm'):
                name = l.split(':')[1]
                lineno = int(l.split(':')[2])
                warning = 'L%04d: %s: %%OWASP-CR-SourceCodeDesign: Django ModelForm; unsafe Meta class setting with assignment [%s = %s]' % (lineno, self.shortname, name, self.class_func_assign[l])
                self.warnings.append(warning)

            elif re.match(r'^Meta:exclude', l) \
                    and self.__search_imports('ModelForm'):
                name = l.split(':')[1]
                lineno = int(l.split(':')[2])
                warning = 'L%04d: %s: %%OWASP-CR-SourceCodeDesign: Django ModelForm; selective Meta class field exclusion is not recommended [%s = %s]' % (lineno, self.shortname, name, self.class_func_assign[l])
                self.warnings.append(warning)

    def __search_imports(self, name):
        rxp = re.compile('^(import|from).+%s' % name)
        for line in self.imports:
            if rxp.match(line):
                return True
        return False

    def __load_rules(self, rulesfile):
        try:
            f = open(rulesfile, 'r')
        except:
            sys.stderr.write('__load_rules(): failed to open rules file')
            raise

        for row in csv.reader(f, delimiter=',', quotechar='"'):
            if len(row) == 0 or re.match(r'^#.+', row[0]):
                continue
            if row[0] == 'import':
                self.b_imports[row[1]] = row[2]
            elif row[0] == 'string':
                self.b_strings[row[1]] = row[2]
            elif row[0] == 'general':
                self.b_general[row[1]] = row[2]
            elif row[0] == 'template':
                self.b_template[row[1]] = row[2]

            try:
                self.b_imports_re = self.__regex_compile(self.b_imports)
            except:
                raise
            try:
                self.b_strings_re = self.__regex_compile(self.b_strings)
            except:
                raise
            try:
                self.b_general_re = self.__regex_compile(self.b_general)
            except:
                raise
            try:
                self.b_template_re = self.__regex_compile(self.b_template)
            except:
                raise

    def __regex_compile(self, rule_dict):
        try:
            re_dict = [re.compile(r) for r in rule_dict]
        except re.error as e:
            sys.stderr.write('__load_rules(): regex compiled failed for [%s] [%s]' % (r, e))
            raise
        return re_dict

    def __crossdomain_xml(self, filename):
        tree = ET.parse(filename)
        troot = tree.getroot()
        site_control = troot.find('site-control')\
            .attrib['permitted-cross-domain-policies']
        if site_control == 'master-only':
            self.warnings.append('L____: %s: crossdomain "master-only" site control enabled' % (self.shortname))
        elif site_control == 'by-ftp-filename':
            self.warnings.append('L____: %s: URLS ending in crossdomain.xml can serve up cross domain policy' % (self.shortname))
        elif site_control == 'by-content-type':
            self.warnings.append('L____: %s: Files with text/x-cross-domain-policy header can serve up cross domain policy' % (self.shortname))

        for access in troot.findall('allow-access-from'):
            if re.match(r'^\*', access.attrib['domain']):
                self.warnings.append('L____: %s: Wildcard character in domain attrib [%s]' % (self.shortname, access.attrib['domain']))
            if re.match(r'false', access.attrib['secure'], re.IGNORECASE):
                self.warnings.append('L____: %s: Non-secure protocol access for domain [%s]' % (self.shortname, access.attrib['domain']))

    def __rxp_ast_check(self, mstr, node, sset, rset):
        for (p, v) in zip(rset, sset):
            try:
                if p.match(mstr):
                    try:
                        self.warnings.append('L%04d: %s: %s'
                                             % (node.lineno, self.shortname,
                                                sset[v]))
                    except:
                        self.warnings.append('L%04d: %s: %s'
                                             % (-99, self.shortname, sset[v]))
            except:
                sys.stderr.write('rxp_ast_check(): %s' % (re.error))
                raise

    def __istemplate(self):
        if len(self.__grep('{%|%}|{{|}}')) > 0:
            return True
        return False

    def __grep(self, exp):
        if not self.content:
            return []
        i = 0
        mline = []
        rxp = re.compile(exp)
        for line in self.content.split('\n'):
            if rxp.match(line):
                mline.append(i)
            i += 1
        return mline

    def __rxp_nonast_check(self, sset, rset):
        for (p, v) in zip(rset, sset):
            for lineno in self.__grep(v):
                try:
                    self.warnings.append('L%04d: %s: %s' %
                                         (lineno, self.shortname, sset[v]))
                except:
                    pass

    def visit_Import(self, node):
        if self.debug:
            print 'visit_Import(): %s (%d)' % (node.names[0].name, node.lineno)
        for alias in node.names:
            codeline = 'import ' + getattr(alias, 'name')
            self.imports.append(codeline)
            try:
                self.__rxp_ast_check(codeline, node,
                                     self.b_imports, self.b_imports_re)
            except:
                pass
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if self.debug:
            print 'visit_ImportFrom(): %s' % (node.names[0])
        modulename = str(node.module)
        codeline = 'import ' + modulename
        self.imports.append(codeline)
        try:
            self.__rxp_ast_check(codeline, node,
                                 self.b_imports, self.b_imports_re)
        except:
            pass
        for alias in node.names:
            codeline = 'from %s import %s' \
                % (modulename, getattr(alias, 'name'))
            self.imports.append(codeline)
            try:
                self.__rxp_ast_check(codeline, node,
                                     self.b_imports, self.b_imports_re)
            except:
                pass
        self.generic_visit(node)

    def visit_ClassDef(self, node):
        self.classes.append(node.name)
        for statement in ast.iter_child_nodes(node):

            """
            Lets store either Classdef:FuncName() or Classdef:Classdef
            for later reference if we need it.
            """
            if self.rxpobj.match(str(statement)).group(1) \
                == '_ast.FunctionDef' \
                or self.rxpobj.match(str(statement)).group(1) \
                    == '_ast.ClassDef':
                myname = node.name + ':' + statement.name
                if myname not in self.classes:
                    self.classes.append(node.name + ':' + statement.name)

            """
            if we are doing a function definition or a variable
            assignment, we are interested in the LHS, and RHS
            of the code statement
            """
            if self.rxpobj.match(str(statement)).group(1) \
                == '_ast.FunctionDef' \
                or self.rxpobj.match(str(statement)).group(1) \
                    == '_ast.Assign':
                try:
                    clfunctions = self.__process_func_assign(node.body)
                except:
                    clfunctions = []
                for varassign in clfunctions:
                    key = node.name + ':' + varassign[0]
                    self.class_func_assign[key] = varassign[1]

        self.generic_visit(node)

    def __process_func_assign(self, node):
        """
        This method will parse a func/method assignment within
        a class or method within a class.  It will return a list
        of assignments in the form:  target = func.SubMethod.SubSubMethod
        """
        retlist = []
        for statement in node:
            if not self.rxpobj.match(str(statement)).group(1) == '_ast.Assign':
                continue
            for target in statement.targets:
                targetname = getattr(target, 'id') + ':' + str(target.lineno)

                if self.rxpobj.match(str(statement.value)).group(1) \
                        == '_ast.Call':
                    try:
                        rhs_func = getattr(getattr(statement.value, 'func'),
                                           'value')
                    except:
                        raise
                    rhs_funcname = self.__process_id(rhs_func)
                    attr = self.__process_attr(getattr(statement.value, 'func'))
                    rhs = '%s.%s()' % (rhs_funcname, attr)
                    retlist.append([targetname, rhs])

                elif self.rxpobj.match(str(statement.value)).group(1) \
                        == '_ast.Name':
                    retlist.append([targetname, statement.value.id])

                elif self.rxpobj.match(str(statement.value)).group(1) \
                        == '_ast.List':
                    mlist = '['
                    for cn in ast.iter_child_nodes(statement.value):
                        if self.rxpobj.match(str(cn)).group(1) == '_ast.Str':
                            mlist += '\'%s\',' % (cn.s)
                    mlist = mlist[:-1] + ']'
                    retlist.append([targetname, mlist])

                elif self.rxpobj.match(str(statement.value)).group(1) \
                        == '_ast.Str':
                    retlist.append([targetname, statement.value.s])
        return retlist

    def __process_id(self, node):
        """
        This method recursively descends down the function
        call attributes  of the left hand side of a Python expression,
        and returns related string attributes in any AST node of
        type 'Name'.
        """
        m = self.rxpobj.match(str(node))
        retval = ''
        if m.group(1) == '_ast.Name':
            retval = getattr(node, 'id')
        elif m.group(1) == '_ast.Attribute':
            retval += self.__process_id(node.value)
        return retval

    def __process_attr(self, node):
        """
        This method recursively descends down the function call
        attributes of the right hand side of a Python expression,
        and returns related string attributes in any
        AST node of type 'Name'.
        """
        m = self.rxpobj.match(str(node.value))
        retval = ''
        if m.group(1) == '_ast.Name':
            retval = getattr(node, 'attr')
        elif m.group(1) == '_ast.Attribute':
            retval += self.__process_attr(node.value) + '.' \
                + getattr(node, 'attr')
        return retval

    def visit_Str(self, node):
        if self.debug:
            print 'visit_Str(): %s' % (str(node.s))
        try:
            self.__rxp_ast_check(str(getattr(node, 's')), node,
                                 self.b_strings, self.b_strings_re)
        except:
            pass
        self.generic_visit(node)
