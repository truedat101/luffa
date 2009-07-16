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

    * python scan.py ../../../examples/luffaproject.conf

"""
import sys
import os
import unittest
import string
import re
import getopt

# Pattern based on fine work of http://www.regular-expressions.info/email.html, RFC 2822, and your local Audi Dealer
# I could write these, but we'd have a leaky sieve
emailRegexPattern = r"[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
# XXX This needs work....
# domainnameRegexPattern = r"(?:[a-z0-9!#$%&'*+/=?^@_`{|}~]+)+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~]+)?(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~]+)"
# Below, inspired by # This one is a combo of http://tools.devshed.com/webmaster-tools/regex-extractor/ and the URL above
domainnameRegexPattern = r"[A-Z0-9][A-Z0-9.-]{0,61}[A-Z0-9]\.(?:com|org|net|gov|mil|biz|info|mobi|name|aero|jobs|museum)"

#  [-a-z0-9]+(\.[-a-z0-9]+)*\.(com|edu|info)  http://regex.info/listing.cgi?ed=2&p=all
# need ip v6
# Great inspiration here: http://www.regexlib.com/DisplayPatterns.aspx?cattabindex=1&categoryId=2
# IPV6 ^((([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){6}:[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){5}:([0-9A-Fa-f]{1,4}:)?[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){4}:([0-9A-Fa-f]{1,4}:){0,2}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){3}:([0-9A-Fa-f]{1,4}:){0,3}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){2}:([0-9A-Fa-f]{1,4}:){0,4}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){6}((\b((25[0-5])|(1\d{2})|(2[0-4]\d)|(\d{1,2}))\b)\.){3}(\b((25[0-5])|(1\d{2})|(2[0-4]\d)|(\d{1,2}))\b))|(([0-9A-Fa-f]{1,4}:){0,5}:((\b((25[0-5])|(1\d{2})|(2[0-4]\d)|(\d{1,2}))\b)\.){3}(\b((25[0-5])|(1\d{2})|(2[0-4]\d)|(\d{1,2}))\b))|(::([0-9A-Fa-f]{1,4}:){0,5}((\b((25[0-5])|(1\d{2})|(2[0-4]\d)|(\d{1,2}))\b)\.){3}(\b((25[0-5])|(1\d{2})|(2[0-4]\d)|(\d{1,2}))\b))|([0-9A-Fa-f]{1,4}::([0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4})|(::([0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){1,7}:))$
# IPV4 SIMPLE [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}
# some better IPV6 regexes: http://forums.dartware.com/viewtopic.php?t=452
# XXX I suck at these, by the way....
ipaddressRegexPattern = r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"

class Scan:
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
        # XXX DEBUG print "called deepScan(" + currentPath + ")"
        if (os.path.isdir(currentPath)):
            files = os.listdir(currentPath)
            for f in files:
                # XXX Debug print files
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
                    #  Also, not really robust...if an env variable is incorrect, you have a none type and the rstrip will fail
                    namesPattern = self.luffaWatchlistEnv.get('watchlist.names').rstrip()
                    companiesPattern = self.luffaWatchlistEnv.get('watchlist.companies').rstrip()
                    badwordsPattern = self.luffaWatchlistEnv.get('watchlist.badwords').rstrip()
                    opensourceLicensePattern = self.luffaLicenseEnv.get('license.opensource').rstrip()
                    hostnamesPattern = self.luffaWatchlistEnv.get('watchlist.hostnames').rstrip()
                    ipaddressesPattern = self.luffaWatchlistEnv.get('watchlist.ipaddresses').rstrip()
                    emailPattern = self.luffaWatchlistEnv.get('watchlist.emailaddresses').rstrip()

                    # XXX DEBUG
                    # print "Loaded Names Scan (pattern=%s)" % (namesPattern)
                    # print "Loaded Companies Scan (pattern=%s)" % (companiesPattern)
                    # print "Loaded Badwords Scan (pattern=%s)" % (badwordsPattern)
                    # print "Loaded License Scan (pattern=%s)" % (opensourceLicensePattern)
                    for line in afile:
                        i+=1
                        # Scan for watchlist.names
                        # XXX Do some big refactoring here
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
                        result = self.generalPatternScan(line, emailPattern, emailRegexPattern)
                        if (len(result) > 0):
                            print "Flag potential Emails issue on line %d" %i + ", found following items:",result[0:len(result)]

#                        # Scan for watchlist.hostnames
                        result = self.generalPatternScan(line, hostnamesPattern, domainnameRegexPattern)
                        if (len(result) > 0):
                            print "Flag potential Hostname issue on line %d" %i + ", found following items:",result[0:len(result)]

#                        # Scan for watchlist.ipaddresses
                        result = self.generalPatternScan(line, ipaddressesPattern, ipaddressRegexPattern)
                        if (len(result) > 0):
                            print "Flag potential IP Address issue on line %d" %i + ", found following items:",result[0:len(result)]

                        # Scan for license.opensource
                        p = re.compile(r"" + opensourceLicensePattern + "", re.IGNORECASE)
                        result = p.findall(line)
                        if (len(result) > 0):
                            print "Flag potential Opensource License reference on line %d" %i + ", found following items:",result[0:len(result)]
                # else:
                    # XXX DEBUG print "skipping file non-whitelist file %s" % (currentPath) # Without the regex matching, this will print extra times for each file type not matched

    def generalPatternScan(self, textString, pattern, wildcard):
        # print "Loaded email pattern from watchlist.emailaddress %s of length=%d" % (pattern, len(pattern))
        if ((pattern.find("*",0) == 0) and (len(pattern) == 1)):
            pattern = wildcard
        p = re.compile(r"" + pattern + "", re.IGNORECASE)
        matches = p.findall(textString)
        return matches
    # XXX If we don't need main, we don't need this
    def usage(self):
        print __doc__
    # XXX This gets ignored...., so remove it
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
        mainLuffa = Scan()
        propsRead = mainLuffa.initEnv(config)
        if (propsRead > 0):
            mainLuffa.deepScan(mainLuffa.luffaProjectEnv["project.path.uri"].rstrip())
        else:
            print "ERROR: No properties were read.  Go find out why."
# XXX Is it even good style to include the tests directly in the library class file
class scanTests(unittest.TestCase):
    def setUp(self):
        print "Setting up"
        self.aLuffa = Scan()
    def testInitEnv(self):
        self.assert_(self)
        print os.path.abspath('.')
        propsRead = self.aLuffa.initEnv("../../../examples/luffaproject.conf")
        self.assert_(propsRead > 0)
        self.assert_(propsRead == 13)
        self.assert_(self.aLuffa.luffaProjectEnv)
        self.assert_(self.aLuffa.luffaProjectEnv.get('project.fullname'))
        print "# of props read=%d" % propsRead
    def testDeepScan1(self):
        propsRead = self.aLuffa.initEnv("../../../examples/luffaproject.conf")
        self.aLuffa.deepScan(str(self.aLuffa.luffaProjectEnv["project.path.uri"]).rstrip()) # Watch the newlines.  Why?
    def testWatchlistNames(self):
        propsRead = self.aLuffa.initEnv("../../../examples/luffaproject.conf")
        pattern = self.aLuffa.luffaWatchlistEnv.get('watchlist.names').rstrip()
        print "loaded watchlist.names pattern = %s" % pattern
        p = re.compile(r"" + pattern + "", re.IGNORECASE)
        result1 = p.findall("Mike and David are cool")
        self.assert_(result1 > 0)
        print result1
        self.assert_(len(result1) == 2)
    def testWatchlistCompanies(self):
        propsRead = self.aLuffa.initEnv("../../../examples/luffaproject.conf")
        pattern = self.aLuffa.luffaWatchlistEnv.get('watchlist.companies').rstrip()
        print "loaded watchlist.companies pattern = %s" % pattern
        p = re.compile(r"" + pattern + "", re.IGNORECASE)
        result1 = p.findall("The time has come for Microsoft to fall and for the titans of industry to bow to a new leader, Sun-Micro-Google Inc.")
        self.assert_(result1 > 0)
        print result1
        self.assert_(len(result1) == 3)
    def testLicenseOpensource(self):
        propsRead = self.aLuffa.initEnv("../../../examples/luffaproject.conf")
        pattern = self.aLuffa.luffaLicenseEnv.get('license.opensource').rstrip()
        print "loaded watchlist.companies pattern = %s" % pattern
        p = re.compile(r"" + pattern + "", re.IGNORECASE)
        result1 = p.findall("If you use BSD, then you might want to consider an MIT LICENSE, or just jump ahead to GPL.")
        self.assert_(result1 > 0)
        print result1
        self.assert_(len(result1) == 3)
    def testGeneralPatternScan(self):
        propsRead = self.aLuffa.initEnv("../../../examples/luffaproject.conf")
        # Test for emails
        result1 = self.aLuffa.generalPatternScan("Email me at dkords1@go.com if you want to reach my spam bucket.  If you want to try reaching me at dkords at dot com, that won't work, and please never try me at dk.or@d.s or dk@o.rds", self.aLuffa.luffaWatchlistEnv.get('watchlist.emailaddresses').rstrip(), emailRegexPattern)
        self.assert_(result1 > 0)
        print result1
        self.assert_(len(result1) == 3)
        # Test for hostnames
        result1 = self.aLuffa.generalPatternScan("WE use wikipedia.com for lookup of real information, and www.google.com for lookup of bogus information.  I like to think that any site abc.123.org should be permitted", self.aLuffa.luffaWatchlistEnv.get('watchlist.hostnames').rstrip(), domainnameRegexPattern)
        self.assert_(result1 > 0)
        print result1
        self.assert_(len(result1) == 3)
        # Test for IP Addresses
        result1 = self.aLuffa.generalPatternScan("If you use localhost, 127.0.0.1, or change your subnet to 255.255.255.0, then be careful not to mix up the network with your default gateway at 192.168.0.1", self.aLuffa.luffaWatchlistEnv.get('watchlist.ipaddresses').rstrip(), ipaddressRegexPattern)
        self.assert_(result1 > 0)
        print result1
        self.assert_(len(result1) == 3)
    def tearDown(self):
        print "tearing down"
# NOTE: This one overrides any calls into main, so unittest will always get run!  XXX
if __name__ == '__main__':
    unittest.main() # From within the IDE or from the shell, we'll run tests automatically
else:
    pass # Module Imported by another module, which is what we want mostly