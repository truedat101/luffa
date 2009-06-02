#!/usr/bin/env python
try:
    from setuptools import setup, find_packages
except:
    from distutils.core import setup

import sys
import os

classifiers = [
    'Development Status :: 3 - Alpha'
  , 'Environment :: Console'
  , 'Intended Audience :: Developers'
  , 'License :: OSI Approved :: MIT License'
  , 'Natural Language :: English'
  , 'Operating System :: MacOS :: MacOS X'
  , 'Operating System :: POSIX'
  , 'Programming Language :: Python'
  , 'Topic :: Internet :: WWW/HTTP :: WSGI :: Server'
   ]

setup( name = 'luffa'
     , version = '0.111'
     , package_dir = {'':'src'}
     , packages = [ 'luffa'
                  , 'luffa.tools'
                   ]
     , scripts = ['luffa']
     , description = 'Luffa daily, for reduced legal encumbrances.'
     , author = 'David J. Kordsmeier'
     , author_email = 'dkords@gmail.com'
     , url = 'http://github.com/'
     , classifiers = classifiers
      )
