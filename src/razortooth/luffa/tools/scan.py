#!/usr/bin/env python
# encoding: utf-8
#
#scan.py
#
#Created by David J. Kordsmeier on 2009-01-30.
#Copyright (c) 2009 Razortooth Communications, LLC. All rights reserved.
#
#Redistribution and use in source and binary forms, with or without modification,
#are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright notice,
#      this list of conditions and the following disclaimer.
#
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
#    * Neither the name of Razortooth Communications, LLC, nor the names of its
#      contributors may be used to endorse or promote products derived from this
#      software without specific prior written permission.
#
#THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
#ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
#ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
#ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

r"""Releasing into open source should not be done lightly when you are dealing with your
company’s IP, someone else’s IP, or other people’s IP. It’s OPIPP (like the song, OPP).
There is typically too much risk to rush something out for purposes of a press release
or because management wants to say they now do open source. Luffa is a set of tools to
walk you through what you need to worry about in taking a closed source project into the
Open Soruce community. Luffa scans a directory tree (source, docs, or whatever you choose),
and based on a configuration file, scans white listed files for potential issues, and flags
any potential items that require review by a human. This alone should be able to help you
gather enough information to get the lawyers off your back, make the boss happy, and get
you home in time for Dancing With the Stars.

python scan.py -c=[config file path]
    Scans through the specified source directory in the config file and generates a report for
    whitelisted file with line #s related to Licenses, Programmer Names, Company Names, Email Addresses, and
    Bad Words.  This is currently the only supported mode of execution.
examples:

    * python scan.py ../../../../examples/luffaproject.conf

"""
import sys
import os
import unittest
import string
import re
import getopt

# Pattern based on fine work of http://www.regular-expressions.info/email.html, RFC 2822, and your local Audi Dealer
# I could write these, but we'd have a leaky sieve
emailRegexPattern = r"(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"

class scan:
    confFile = 0
    lines = 0
    luffaProjectEnv = {}
    luffaLicenseEnv = {}
    luffaWatchlistEnv = {}
    luffaReportEnv = {}

    def __init__(self):
        print "Scanning project"
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
            confFile.close()
        else:
            print "Error: Cannot open file $s" % siteFile
        return (len(self.luffaLicenseEnv) + len(self.luffaWatchlistEnv) + len(self.luffaProjectEnv) + len(self.luffaReportEnv))
    def deepScan(self, currentPath):
        currentPath = os.path.abspath(currentPath)
        if (os.path.isdir(currentPath)):
            files = os.listdir(currentPath)
            for f in files:
                print files
                self.deepScan(os.path.join(currentPath, f))
        else:
            # XXX TODO Make sure this section handles double byte character encodings
            # XXX TODO load the regular expressions once, not each file
            extList = self.luffaProjectEnv.get("project.source.ext.whitelist")
            for ext in extList.split(","): # Convert this to a regex, more efficient
                if (currentPath.endswith(ext)): # XXX TODO FIX this to handle upper case, also, this is wrong since it should check all file types in one step
                    print "--------->initiating scan on %s, matches whitelist extension=%s" % (currentPath, ext)
                    afile = open(currentPath, 'rU')
                    i = 0
                    #  Load these during init?
                    namesPattern = self.luffaWatchlistEnv.get('watchlist.names').rstrip()
                    companiesPattern = self.luffaWatchlistEnv.get('watchlist.companies').rstrip()
                    badwordsPattern = self.luffaWatchlistEnv.get('watchlist.badwords').rstrip()
                    opensourceLicensePattern = self.luffaLicenseEnv.get('license.opensource').rstrip()
                    print "Loaded Names Scan (pattern=%s)" % (namesPattern)
                    print "Loaded Companies Scan (pattern=%s)" % (companiesPattern)
                    print "Loaded Badwords Scan (pattern=%s)" % (badwordsPattern)
                    print "Loaded License Scan (pattern=%s)" % (opensourceLicensePattern)
                    for line in afile:
                        i+=1
                        # Scan for watchlist.names
                        p = re.compile(r"" + namesPattern + "", re.IGNORECASE)
                        result = p.findall(line)
                        if (len(result) > 0):
                            print "Flag potential Name issue on line %d" %i + ", found following items:",result[0:len(result)]
                        # Scan for watchlist.companies
                        p = re.compile(r"" + companiesPattern + "", re.IGNORECASE)
                        result = p.findall(line)
                        if (len(result) > 0):
                            print "Flag potential Companies issue on line %d" %i + ", found following items:",result[0:len(result)]

                        # Scan for watchlist.badwords
                        p = re.compile(r"" + badwordsPattern + "", re.IGNORECASE)
                        result = p.findall(line)
                        if (len(result) > 0):
                            print "Flag potential Badword issue on line %d" %i + ", found following items:",result[0:len(result)]

                        # Scan for watchlist.emailaddresses
                        result = self.emailScan(line)
                        if (len(result) > 0):
                            print "Flag potential Emails issue on line %d" %i + ", found following items:",result[0:len(result)]

                        # Scan for license.opensource
                        p = re.compile(r"" + opensourceLicensePattern + "", re.IGNORECASE)
                        result = p.findall(line)
                        if (len(result) > 0):
                            print "Flag potential Opensource License reference on line %d" %i + ", found following items:",result[0:len(result)]
                else:
                    print "skipping file non-whitelist file %s" % (currentPath) # Without the regex matching, this will print extra times for each file type not matched
    def emailScan(self, textString):
        pattern = self.luffaWatchlistEnv.get('watchlist.emailaddresses').rstrip()
        # print "Loaded email pattern from watchlist.emailaddress %s of length=%d" % (pattern, len(pattern))
        if ((pattern.find("*",0) == 0) and (len(pattern) == 1)):
            pattern = emailRegexPattern
        # XXX TODO: Move this into init
        # else:
        #    print "Using a custom regex pattern for email"
        # print "loaded watchlist.emailaddresses pattern = %s" % pattern
        p = re.compile(r"" + pattern + "", re.IGNORECASE)
        matches = p.findall(textString)
        return matches
    def usage(self):
        print __doc__
    def main(argv):
        try:
            opts, args = getopt.getopt(argv, "hc:d", ["help", "config="])
        except getopt.GetoptError:
            usage()
            sys.exit(2)
        for opt, arg in opts:
            if opt in ("-h", "--help"):
                usage()
                sys.exit()
            elif opt == '-d':
                global _debug
                _debug = 1
            elif opt in ("-c","--config"):
                config = arg
        command = "".join(args) # We don't currently need this, but may use it later, putting it here before I forget
        mainLuffa = scan()
        propsRead = mainLuffa.initEnv(config)
        if (propsRead > 0):
            mainLuffa.deepScan(mainLuffa.luffaProjectEnv["project.path.uri"].rstrip())
        else:
            print "ERROR: No properties were read.  Go find out why."
# XXX Is it even good style to include the tests directly in the library class file
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
    def testDeepScan1(self):
        propsRead = self.aLuffa.initEnv("../../../../examples/luffaproject.conf")
        self.aLuffa.deepScan(str(self.aLuffa.luffaProjectEnv["project.path.uri"]).rstrip()) # Watch the newlines.  Why?
    def testWatchlistNames(self):
        propsRead = self.aLuffa.initEnv("../../../../examples/luffaproject.conf")
        pattern = self.aLuffa.luffaWatchlistEnv.get('watchlist.names').rstrip()
        print "loaded watchlist.names pattern = %s" % pattern
        p = re.compile(r"" + pattern + "", re.IGNORECASE)
        result1 = p.findall("Mike and David are cool")
        self.assert_(result1 > 0)
        print result1
        self.assert_(len(result1) == 2)
    def testWatchlistCompanies(self):
        propsRead = self.aLuffa.initEnv("../../../../examples/luffaproject.conf")
        pattern = self.aLuffa.luffaWatchlistEnv.get('watchlist.companies').rstrip()
        print "loaded watchlist.companies pattern = %s" % pattern
        p = re.compile(r"" + pattern + "", re.IGNORECASE)
        result1 = p.findall("The time has come for Microsoft to fall and for the titans of industry to bow to a new leader, Sun-Micro-Google Inc.")
        self.assert_(result1 > 0)
        print result1
        self.assert_(len(result1) == 3)
    def testLicenseOpensource(self):
        propsRead = self.aLuffa.initEnv("../../../../examples/luffaproject.conf")
        pattern = self.aLuffa.luffaLicenseEnv.get('license.opensource').rstrip()
        print "loaded watchlist.companies pattern = %s" % pattern
        p = re.compile(r"" + pattern + "", re.IGNORECASE)
        result1 = p.findall("If you use BSD, then you might want to consider an MIT LICENSE, or just jump ahead to GPL.")
        self.assert_(result1 > 0)
        print result1
        self.assert_(len(result1) == 3)
    def testEmailScan(self):
        propsRead = self.aLuffa.initEnv("../../../../examples/luffaproject.conf")
        result1 = self.aLuffa.emailScan("Email me at dkords1@go.com if you want to reach my spam bucket.  If you want to try reaching me at dkords at dot com, that won't work, and please never try me at dk.or@d.s or dk@o.rds")
        self.assert_(result1 > 0)
        print result1
        self.assert_(len(result1) == 3)
    def tearDown(self):
        print "tearing down"
if __name__ == '__main__':
    unittest.main()