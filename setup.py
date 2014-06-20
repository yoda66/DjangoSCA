#!/usr/bin/env python

import os
from setuptools import setup, find_packages

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(name='DjangoSCA',
   version='1.3e',
   description='Django Static Source Code Analyzer',
   long_description = """
DjangoSCA is a python based Django project source code security auditing system
that makes use of the Django framework itself, the Python Abstract Syntax Tree
(AST) library, and regular expressions.

Django projects are laid out in a directory structure that conforms to a
standard form using known classes, and standard file naming such as
settings.py, urls.py, views.py, and forms.py.

DjangoSCA is designed for the user to pass the root directory of the
Django project as an argument to the program, from which it will
recursively descend through the project files and perform source code
checks on all python source code, and Django template files.
""",
   author='Joff Thyer',
   author_email='jsthyer@gmail.com',
   license='GPLv3',
   url='https://bitbucket.org/jsthyer/djangosca',
   scripts = ['djangoSCA.py'],
   packages = find_packages(),
   data_files = [('/usr/local/etc',['djangoSCA.rules'])]
)

