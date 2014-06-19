#!/usr/bin/env python

import sys
import os
import re
import datetime
import argparse
from djangoSCAclasses.ContentReader import ContentReader
from djangoSCAclasses.SettingsCheck import SettingsCheck
from djangoSCAclasses.MyParser import MyParser


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
    def __init__(self, projdir, fullpath, rulesfile, filehandle):
        try:
            ContentReader.__init__(self, projdir, fullpath)
        except:
            raise
        self.rulesfile = rulesfile
        self.filehandle = filehandle

    def parseme(self):
        try:
            parser = MyParser(self.rulesfile, self.filehandle)
        except:
            raise
        if re.match(r'.+\.py$', self.shortname):
            parser.ast_parse(self.shortname, self.content)
        parser.nonast_parse(self.projdir, self.shortname, self.content)
        return parser.print_warnings()


def spin_thing(outFH, i):
    # prime number controls speed of spinny thing
    prime = 23
    mystr = '/-\\|'
    if outFH != sys.stdout and not (i % prime):
        sys.stdout.write('%s\x08'
                         % (mystr[i % len(mystr):i % len(mystr) + 1]))
        sys.stdout.flush()
    return i + 1


def show_summary(outFH, fext, fwarn):
    out = '\n[*] Stage 2: File Analysis Summary\n'
    for k in sorted(fext.iterkeys()):
        out += '    [-] Extension [.%-4s]: %6d files, %4d warnings\n' % \
            (k, fext[k], fwarn[k])
    out += """\
    [+] template files are identified by regular expression match.
    [+] many xml files may exist, but only crossdomain.xml is analyzed.
    [+] all python scripts will be analyzed."""
    if outFH != sys.stdout:
        outFH.write(out)
    sys.stdout.write(out)


def get_settings_path(base_dir):
    for root, dirs, files in os.walk(base_dir):
        for f in files:
            if f.endswith("settings.py"):
                return os.path.dirname(os.path.join(root, f))

# start of main code
if __name__ == "__main__":

    TITLE = 'DjangoSCA'
    VERSION = '1.3'

    # program description
    desc = """\
DjangoSCA is a static security code analysis tool for Django project analysis.
It performs sanity checks on 'settings.py' files with recommendations for
improving security, and also performs a recursive directory search analysis
across all of the source code of a project.  Python files are parsed using
the native python abstract syntax tree (AST) class.  All file extensions
specified are also analyzed using regular expression checks.
Where possible, Django context specific analysis is performed within the model,
view, controller (MVC) paradigm."""

    # parse arguments
    ap = argparse.ArgumentParser(
        usage="""\
djangoSCA.py -r <rules file> -o <output file> <Django Project Dir>
Version %s, Author: Joff Thyer, (c) 2013"""
        % (VERSION), description=desc)

    ap.add_argument('DjangoProjectDir', help='Django Project Directory')
    ap.add_argument('-s', '--settings', default='settings.py',
                    help='Django settings.py ("settings.py" is the default)')
    ap.add_argument('-i', '--ignore', action='append',
                    help='Ignore directories. eg, --ignore foo --ignore bar')
    ap.add_argument('-r', '--rules', default='/usr/local/etc/djangoSCA.rules',
                    help='DjangoSCA Rules File (default is "djangoSCA.rules")')
    ap.add_argument('-o', '--output',
                    help='Output Text File (default output to screen)')
    args = ap.parse_args()

    if not os.path.isdir(args.DjangoProjectDir):
        sys.stderr.write('project directory does not exist')
        sys.exit(1)

    if args.output:
        try:
            outFH = open(args.output, 'w')
        except:
            sys.stderr.write('failed to open output file')
            sys.exit(1)
    else:
        outFH = sys.stdout

    outFH.write("""
[*]___________________________________________________________
[*]
[*] %s Version %s
[*] Author: Joff Thyer (c) 2013
[*] Project Dir/Name..: %s
[*] Date of Test......: %s
[*]___________________________________________________________

[*]---------------------------------
[*] STAGE 1: Project Settings Tests
[*]---------------------------------

""" % (TITLE, VERSION, args.DjangoProjectDir,
        datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))

    if outFH != sys.stdout:
        print """[*] %s Version %s
[*] Author: Joff Thyer, (c) 2013
[*] Processing Stage 1: [settings.py]""" % (TITLE, VERSION)

    try:
        SettingsCheck(get_settings_path(args.DjangoProjectDir) + "/"
                      + args.settings, args.rules, outFH)
    except:
        raise

    outFH.write("""

[*]---------------------------------------------
[*] STAGE 2: Testing ALL directories and files
[*] .... Warning - This may take some time ....
[*]---------------------------------------------

""")

    if outFH != sys.stdout:
        sys.stdout.write('[*] Processing Stage 2: '
                         + 'Full project directory recursion: [ ]\x08\x08')
        sys.stdout.flush()

    spincount = 0
    rxp = re.compile(r'^[a-zA-Z0-9]+.+\.(py|html|txt|xml)$')
    file_ext = {}
    file_ext_warnings = {}

    for root, dirs, files in os.walk(args.DjangoProjectDir, topdown=True):
        if args.ignore:
            exclude = set(args.ignore)
            dirs[:] = [d for d in dirs if d not in exclude]
        for f in files:
            fullpath = root + '/' + f
            m = rxp.match(f)
            if not m:
                continue

            spincount = spin_thing(outFH, spincount)
            if m.group(1) not in file_ext:
                file_ext[m.group(1)] = 0
                file_ext_warnings[m.group(1)] = 0
            file_ext[m.group(1)] += 1
            try:
                dfc = DjangoFileCheck(args.DjangoProjectDir,
                                      fullpath, args.rules, outFH)
                file_ext_warnings[m.group(1)] += dfc.parseme()
            except:
                raise

    show_summary(outFH, file_ext, file_ext_warnings)
    print '\n[*] Test Complete'
    if all(v == 0 for v in file_ext_warnings.values()):
        sys.exit(0)
    else:
        sys.exit(1)
