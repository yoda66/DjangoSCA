#!/usr/bin/env python

import sys, os, re
import datetime
import argparse
from ContentReader import ContentReader
from SettingsCheck import SettingsCheck
from MyParser import MyParser


class DjangoFileCheck(ContentReader):

  """
  This class extends the base ContentReader class to
  include the core 'parseme()' method.  In turn, this will
  parse a Python source file with .py extension using the
  abstract syntax tree (AST).  It will then sequentially
  parse files ending with .py, .html, and .txt with a regular
  expression parser as well as performing a crossdomain.xml
  file check.
  """
  def __init__(self,projdir,fullpath,rulesfile,filehandle):
    try:
      ContentReader.__init__(self,projdir,fullpath)
    except:
      raise
    self.rulesfile = rulesfile
    self.filehandle = filehandle


  def parseme(self):
    try:
      parser = MyParser(self.rulesfile,self.filehandle)
    except:
      raise
    if re.match(r'.+\.py$',self.shortname):
      parser.ast_parse(self.shortname,self.content)
    parser.nonast_parse(self.projdir,self.shortname,self.content)
    return parser.print_warnings()



def spin_thing(outFH,i):
  # prime number controls speed of spinny thing
  prime = 23
  mystr = '/-\\|'
  if outFH != sys.stdout and not (i % prime):
    sys.stdout.write('%s\x08' % \
	(mystr[i%len(mystr):i%len(mystr)+1]))
    sys.stdout.flush()
  return i+1


def show_summary(outFH,fext,fwarn):
  out = '\n\r[*] Stage 2: File Analysis Summary\n'
  for k in sorted(fext.iterkeys()):
    out += '  [-] Extension [.%-4s]: %6d files, %4d warnings\n' % (k,fext[k],fwarn[k])
  out += '  ** Note: only recognized template files with extension html or txt are analyzed.\n'
  out += '           only crossdomain.xml named files are analyzed.  All python is analyzed.\n'
  if outFH != sys.stdout:
    outFH.write(out)
  sys.stdout.write(out)



# parse arguments
ap = argparse.ArgumentParser(description='Author: Joff Thyer (c) 2013')
ap.add_argument('projdir',\
	help='Django Project Directory')
ap.add_argument('-r','--rules',default='tangocheck.rules',\
	help='TangoCheck Rules File')
ap.add_argument('-o','--output',\
	help='Results Output Text File')
args = ap.parse_args()

if not os.path.isdir(args.projdir):
  sys.stderr.write('project directory does not exist or is not a directory')
  sys.exit(1)

if args.output:
  try:
    outFH = open(args.output,'w')
  except:
    sys.stderr.write('failed to open output file')
    sys.exit(1)
else:
  outFH = sys.stdout


outFH.write("""
[*]___________________________________________________________
[*]
[*] TangoCheck Version 1.0
[*] Author: Joff Thyer (c) 2013
[*] Project Dir/Name..: %s
[*] Date of Test......: %s
[*]___________________________________________________________

[*]---------------------------------
[*] STAGE 1: Project Settings Tests 
[*]---------------------------------

""" % (args.projdir,datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
try:
  if outFH != sys.stdout:
    print """[*] TangoCheck Version 1.0
[*] Author: Joff Thyer, (c) 2013
[*] Processing Stage 1: [settings.py]"""
  SettingsCheck(args.projdir+'/settings.py',args.rules,outFH)
except:
  raise

outFH.write("""

[*]---------------------------------------------
[*] STAGE 2: Testing ALL directories and files
[*] .... Warning - This may take some time ....
[*]---------------------------------------------

""")

if outFH != sys.stdout:
  sys.stdout.write('[*] Processing Stage 2: Full project directory recursion: [ ]\x08\x08')
  sys.stdout.flush()

spincount = 0
rxp = re.compile(r'^[a-zA-Z0-9]+.+\.(py|html|txt|xml)$')
file_ext = {}
file_ext_warnings = {}
for root, dirs, files in os.walk(args.projdir):
  for f in files:

    fullpath = root + '/' + f
    m = rxp.match(f)
    if m:
      spincount = spin_thing(outFH,spincount)
      if m.group(1) not in file_ext:
        file_ext[m.group(1)] = 0
        file_ext_warnings[m.group(1)] = 0
      file_ext[m.group(1)] += 1
      try:
        dfc = DjangoFileCheck(args.projdir,fullpath,args.rules,outFH)
        file_ext_warnings[m.group(1)] += dfc.parseme()
      except:
        raise

show_summary(outFH,file_ext,file_ext_warnings)
if outFH != sys.stdout: print '\r\n[*] Test Complete'

