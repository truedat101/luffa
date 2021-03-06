#!/usr/bin/env python
# encoding: utf-8
#
#ScanReport.py
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

python ScanReport.py -c [config file path]
    Scans through the specified source directory in the config file and generates a report for
    whitelisted file with line #s related to Licenses, Programmer Names, Company Names, Email Addresses, and
    Bad Words.  This is currently the only supported mode of execution.
examples:

    * python ScanReport.py ../../../../examples/luffaproject.conf

"""
import sys
import getopt
from luffa.tools import Scan

class ScanReport:

    def __init__(self):
        print "Scanning project"

    def main(argv):
        config = "../../../../examples/luffaproject.conf"
        try:
            opts, args = getopt.getopt(argv, "hc:d", ["help", "config="])
        except getopt.GetoptError:
            print __doc__
            sys.exit(2)
        for opt, arg in opts:
            if opt in ("-h", "--help"):
                print __doc__
                sys.exit()
            elif opt == '-d':
                global _debug
                _debug = 1
            elif opt in ("-c","--config"):
                config = arg
        command = "".join(args) # We don't currently need this, but may use it later, putting it here before I forget
        mainLuffa = Scan.Scan()
        propsRead = mainLuffa.initEnv(config)
        if (propsRead > 0):
            mainLuffa.deepScan(mainLuffa.luffaProjectEnv["project.path.uri"].rstrip())
        else:
            print "ERROR: No properties were read.  Go find out why."
    if __name__ == '__main__':
      main(sys.argv[1:])
    else:
      # This will be executed in case the
      #    source has been imported as a
      #    module.
      print "ERROR: Module should be run as a command line"
      system.exit(2)