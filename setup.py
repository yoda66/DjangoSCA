#!/usr/bin/env python

from distutils.core import setup
from os.path import join, dirname

setup(name='DjangoSCA',
   version='1.3',
   description='Django Static Source Code Analyzer',
   author='Joff Thyer',
   author_email='jsthyer@gmail.com',
   license='GPLv3',
   url='https://bitbucket.org/jsthyer/djangosca',
   long_description = open(join(dirname(__file__), 'README.md')).read(),
   scripts = ['djangoSCA.py'],
   packages = ['djangoSCAclasses'],
   data_files = [('/usr/local/etc',['djangoSCA.rules'])]
)

