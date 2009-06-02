#!/usr/bin/env python
try:
    from setuptools import setup, find_packages
except:
    from distutils.core import setup

import sys
import os

import luffa.PkgInfo

if float("%d.%d" % sys.version_info[:2]) < 2.5:
	sys.stderr.write("Your Python version %d.%d.%d is not supported.\n" % sys.version_info[:3])
	sys.stderr.write("luffa requires Python 2.5 or newer.\n")
	sys.exit(1)

try:
	## Remove 'MANIFEST' file to force
	## distutils to recreate it.
	## Only in "sdist" stage. Otherwise 
	## it makes life difficult to packagers.
	if sys.argv[1] == "sdist":
		os.unlink("MANIFEST")
except:
	pass

## Don't install manpages and docs when $LUFFA_PACKAGING is set
## This was a requirement of Debian package maintainer. 
if not os.getenv("LUFFA_PACKAGING"):
	man_path = os.getenv("LUFFA_INSTPATH_MAN") or "share/man"
	doc_path = os.getenv("LUFFA_INSTPATH_DOC") or "share/doc/packages"
	data_files = [	
		(doc_path+"/luffa", [ "README", "INSTALL", "NEWS" ]),
		(man_path+"/man1", [ "luffax.1" ] ),
	]
else:
	data_files = None

## XXX TODO: Fix the Topic
classifiers = [
    'Development Status :: 3 - Alpha'
  , 'Environment :: Console'
  , 'Intended Audience :: Developers'
  , 'License :: OSI Approved :: BSD License'
  , 'Natural Language :: English'
  , 'Operating System :: MacOS :: MacOS X'
  , 'Operating System :: POSIX'
  , 'Programming Language :: Python'
  , 'Topic :: Internet :: WWW/HTTP :: WSGI :: Server'
   ]

## Main distutils info
setup(
	## Content description
	name = luffa.PkgInfo.package,
	version = luffa.PkgInfo.version,
	## packages = [ 'luffa', 'luffa.tools' ],
	packages = find_packages(),
	scripts = ['luffax'],
	data_files = data_files,

	## Packaging details
	author = "David J. kordsmeier",
	author_email = "dkords@gmail.com",
	url = luffa.PkgInfo.url,
	license = luffa.PkgInfo.license,
	description = luffa.PkgInfo.short_description,
	long_description = """
%s

Authors:
--------
    David J. Kordsmeier <dkords@gmail.com>
""" % (luffa.PkgInfo.long_description)
	)
