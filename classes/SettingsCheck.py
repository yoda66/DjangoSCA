#!/usr/bin/env python

import tempfile
import shutil
import os
import sys
import re
import csv
try:
    from django.conf import settings
    from django.core.exceptions import ImproperlyConfigured
except:
    sys.stderr.write('django.conf module not found. You must install Django, or enter an environment in which it is installed first. Exiting.\n')
    sys.exit(1)


class SettingsCheck(object):

    """
    This class uses the django.conf module to parse the django settings.py
    file in the same way that django itself does.  This way we can populate
    the django settings class, and then perform our specific checks
    using that class.   In order to properly parse the settings.py file
    without any modifications, we first make a temporary directory and
    copy the settings.py file to that temporary directory.
    Then we append the path to sus.path, and set the DJANGO_SETTINGS_MODULE
    environment variable to the string 'settings' to read the copied file.
    Local class rule base checks performed include:
    - recommended variables
    - recommended middleware
    - recommended apps
    - required fields
    - password hashing order
    """

    def __init__(self, name, rules, filehandle):
        self.name = name
        self.filehandle = filehandle
        os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'

        # if we don't find the file, then just fail with a simple error
        if not os.path.isfile(name):
            self.filehandle.write(
                '[*] Cannot find a Django settings file [%s]\n' % (name))
            return

        # mkdir temp directory and append to sys.path
        try:
            self.tempdir = tempfile.mkdtemp()
            sys.path.append(self.tempdir)
        except:
            raise

        # copy settings.py file to temp dir
        try:
            shutil.copy(self.name, self.tempdir)
        except:
            raise

        self.b_apps = {}
        self.b_fields = {}
        self.b_middleware = {}
        self.b_vars = {}

        # load the rules file
        try:
            self.__load_rules(rules)
        except:
            raise

        # start running the rules checks
        self.scan()

    def __del__(self):
        try:
            shutil.rmtree(self.tempdir)
        except:
            pass

    def __load_rules(self, rulesfile):
        try:
            f = open(rulesfile, 'r')
        except:
            sys.stderr.write('__load_rules(): failed to open rules file\n')
            raise

        for row in csv.reader(f, delimiter=',', quotechar='"'):
            if len(row) == 0 or re.match(r'^#.+', row[0]):
                continue
            if row[0] == 'settings_rec_apps':
                self.b_apps[row[1]] = row[2]
            elif row[0] == 'settings_req_field':
                self.b_fields[row[1]] = ''
            elif row[0] == 'settings_rec_middleware':
                self.b_middleware[row[1]] = ''
            elif row[0] == 'settings_rec_var':
                self.b_vars[row[1]] = row[2]

    def __required_fields(self):
        for field in self.b_fields:
            try:
                if not hasattr(settings, field):
                    self.filehandle.write('[*] %%OWASP-CR-BestPractice: Required field [%s] has no value set.\n' % (field))
            except:
                self.filehandle.write('[*] %%OWASP-CR-BestPractice: Required field [%s] does not exist.\n' % (field))
                pass

    def __recommended_variable_settings(self):
        for v in self.b_vars:
            try:
                value = getattr(settings, v)
                if str(value) != self.b_vars[v]:
                    self.filehandle.write('[*] %%OWASP-CR-BestPractice: Incorrect recommended variable setting [%s = %s]\n' % (v, value))
            except:
                self.filehandle.write('[*] %%OWASP-CR-BestPractice: Recommended variable [%s] does not exist.\n' % (v))
                pass

    def __recommended_middleware(self):
        output = ''
        middleware = []
        try:
            for m in settings.MIDDLEWARE_CLASSES:
                middleware.append(m)
                if not m.startswith('django'):
                    output += '  [-] %OWASP-CR-BestPractice: ' + m + '\n'
            if len(output) > 0:
                self.filehandle.write('[*] %OWASP-CR-BestPractice: Custom MIDDLEWARE_CLASSES:\n')
                self.filehandle.write(output)
        except ImproperlyConfigured as improper:
            self.filehandle.write('[*] Improper configuration error: %s\n' % (improper.message))
        except Exception as e:
            self.filehandle.write('[*] Exception of type %s found: %s\n' % (type(e).__name__, e.message))

        output = ''
        for ms in self.b_middleware:
            if ms not in middleware:
                output += '  [-] %OWASP-CR-BestPractice: consider using "'\
                    + ms + '"\n'
        if len(output) > 0:
            self.filehandle.write('[*] %OWASP-CR-BestPractice: Recommended MIDDLEWARE_CLASSES:\n')
            self.filehandle.write(output)

    def __recommended_apps(self):
        output = ''
        for app in self.b_apps:
            try:
                if app not in getattr(settings, 'INSTALLED_APPS'):
                    output += '  [-] %%OWASP-CR-BestPractice: Consider using installed app "%s" (%s)\n' \
                        % (app, self.b_apps[app])
            except:
                output += '  [-] %%OWASP-CR-BestPractice: Recommended installed app [%s] is not configured.\n' % (app)
            pass

        if len(output) > 0:
            self.filehandle.write('[*] %OWASP-CR-BestPractice: Recommended INSTALLED_APPS:\n')
            self.filehandle.write(output)

    def __password_hashers(self):
        try:
            ph = getattr(settings, 'PASSWORD_HASHERS')
        except:
            return
        if not re.match(r'.+\.(PBKDF2|Bcrypt).+', ph[0]):
            self.filehandle.write('[*] %OWASP-CR-BestPractice: PASSWORD_HASHERS should list PBKDF2 or Bcrypt first!\n')

    def scan(self):
        self.__required_fields()
        self.__recommended_variable_settings()
        self.__recommended_middleware()
        self.__recommended_apps()
        self.__password_hashers()
