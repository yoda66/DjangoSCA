#!/usr/bin/env python

import os
from setuptools import setup, find_packages

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(name='DjangoSCA',
   version='1.3h',
   description='Django Static Source Code Analyzer',
   author='Joff Thyer',
   author_email='jsthyer@gmail.com',
   license='GPLv3',
   url='https://bitbucket.org/jsthyer/djangosca',
   scripts = ['djangoSCA.py'],
   packages = find_packages(),
   data_files = [('/usr/local/etc',['djangoSCA.rules'])]
)

