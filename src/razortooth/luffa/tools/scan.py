#!/usr/bin/env python
# encoding: utf-8
"""
scan.py

Created by David J. Kordsmeier on 2009-01-30.
Copyright (c) 2009 Razortooth Communications, LLC. All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.

    * Neither the name of Razortooth Communications, LLC, nor the names of its
      contributors may be used to endorse or promote products derived from this
      software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import sys
import os
import unittest

class scan:
    confFile = 0
    lines = 0
    luffaProjectEnv = {}
    luffaLicenseEnv = {}
    luffaWatchlistEnv = {}
    luffaReportEnv = {}

    def __init__(self):
        print "Scanning"
    def initEnv(self, projectConf):
        confFile = open(projectConf, 'rU')
        lines = confFile.readlines()
        if confFile:
            # read it in
            print confFile
            for line in lines:
                # Discard comments
                # split each line into key, tuple
                if line[0].find("#", 0) == -1:
                    line = line.split('=')
                    if line[0].find("project") > -1:
                        self.luffaProjectEnv[line[0]] = line[1]
                    elif line[0].find("license") > -1:
                        self.luffaLicenseEnv[line[0]] = line[1]
                    elif line[0].find("watchlist") > -1:
                       self.luffaWatchlistEnv[line[0]] = line[1]
                    elif line[0].find("report") > -1:
                       self.luffaReportEnv[line[0]] = line[1]
                    else:
                       print "Ignoring env property %s" % line
            confFile.close()
        else:
            print "Error: Cannot open file $s" % siteFile
        return (len(self.luffaLicenseEnv) + len(self.luffaWatchlistEnv) + len(self.luffaProjectEnv) + len(self.luffaReportEnv))
class scanTests(unittest.TestCase):
    def setUp(self):
        print "Setting up"
        self.aLuffa = scan()
    def testInitEnv(self):
        self.assert_(self)
        print os.path.abspath('.')
        propsRead = self.aLuffa.initEnv("../../../../examples/luffaproject.conf")
        self.assert_(propsRead > 0)
        self.assert_(self.aLuffa.luffaProjectEnv)
        self.assert_(self.aLuffa.luffaProjectEnv.get('project.fullname'))
        print "# of props read=%d" % propsRead
    def tearDown(self):
        print "tearing down"
if __name__ == '__main__':
    unittest.main()