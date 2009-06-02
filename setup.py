#!/usr/bin/env python

# ...

from distutils.core import setup

setup(name='luffa',
      version='0.11',
      description='luffa: makes open sourcing your proprietary source ez',
      author='David J. Kordsmeier',
      author_email='dkords@gmail.com',
      url=' http://github.com/',
      packages=['razortooth', 'razortooth.luffa', 'razortooth.luffa.tools'],
      long_description="Make a lawyer happy.  Scan your code first.  luffa: makes open sourcing your proprietary source ez.",
      license="Public domain",
      platforms=["any"],
     )
