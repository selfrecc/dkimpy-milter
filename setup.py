#! /usr/bin/python3
# dkimpy-milter: A DKIM signing/verification Milter application
# Author: Scott Kitterman <scott@kitterman.com>
# Copyright 2018,2019 Scott Kitterman
"""    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA."""

from setuptools import setup
import distutils.cmd
import distutils.log
import sys
import os
import subprocess

description = "Domain Keys Identified Mail (DKIM) signing/verifying milter for Postfix/Sendmail."

with open("README.md", "r") as fh:
    long_description = fh.read()


class FileMacroExpand(distutils.cmd.Command):
    description = "Expand @@ variables in input files, simlar to make macros."
    user_options = [
        ('sysconfigdir=', 'e', 'Specify system configuration directory. [/usr/local/etc]'),
        ('sbindir=', 's', 'Specify system binary directory. [/usr/local/sbin]'),
        ('bindir=', 'b', 'Specify binary directory. [/usr/loca/bin]'),
        ('rundir=', 'r', 'Specify run state directory. [/run]'),
    ]

    def initialize_options(self):
        self.sysconfigdir = '/usr/local/etc'
        self.sbindir = '/usr/local/sbin'
        self.bindir = '/usr/local/bin'
        self.rundir = '/run'

    def finalize_options(self):
        self.configdir = self.sysconfigdir + '/dkimpy-milter'
        self.rundir += '/dkimpy-milter'

    def run(self):
        files = ['etc/dkimpy-milter.conf', 'man/dkimpy-milter.conf.5', \
                 'system/dkimpy-milter.service', 'system/dkimpy-milter', \
                 'system/dkimpy-milter.openrc', \
                 'system/socket-activation/dkimpy-milter.service', \
                 'system/socket-activation/dkimpy-milter.socket',]
        for infile in files:
            outfile = ''
            filein = open(infile + '.in')
            for line in filein:
                for function in ["@SYSCONFDIR@", "@CONFDIR@", "@SBINDIR@", "@BINDIR@", "@RUNSTATEDIR@"]:
                    splitline = line.split(function)
                    if len(splitline) > 1:
                        if function == "@SYSCONFDIR@":
                            line = splitline[0] + self.sysconfigdir + splitline[1]
                        elif function == "@CONFDIR@":
                            line = splitline[0] + self.configdir + splitline[1]
                        elif function == "@SBINDIR@":
                            line = splitline[0] + self.sbindir + splitline[1]
                        elif function == "@BINDIR@":
                            line = splitline[0] + self.bindir + splitline[1]
                        elif function == "@RUNSTATEDIR@":
                            line = splitline[0] + self.rundir + splitline[1]
                outfile += line
            out = open(infile, 'w')
            for line in outfile:
                out.write(line)
            out.close()

kw = {}  # Work-around for lack of 'or' requires in setuptools.
try:
    import dns
    kw['install_requires'] = ['dkimpy>=1.0', 'pymilter', 'authres>=1.1.0', 'PyNaCl', 'dnspython>=1.16.0']
except ImportError:  # If PyDNS is not installed, prefer dnspython
    kw['install_requires'] = ['dkimpy>=1.0', 'pymilter', 'authres>=1.1.0', 'PyNaCl', 'Py3DNS']

setup(
    name='dkimpy-milter',
    version='1.2.0',
    author='Scott Kitterman',
    author_email='scott@kitterman.com',
    url='https://launchpad.net/dkimpy-milter',
    description=description,
    long_description=long_description,
    long_description_content_type='text/markdown',
    download_url = "https://pypi.python.org/pypi/dkimpy-milter",
    classifiers= [
        'Development Status :: 5 - Production/Stable',
        'Environment :: No Input/Output (Daemon)',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Natural Language :: English',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Communications :: Email :: Mail Transport Agents',
        'Topic :: Communications :: Email :: Filters',
        'Topic :: Security',
    ],
    packages=['dkimpy_milter'],
    entry_points = {
        'console_scripts' : [
            'dkimpy-milter = dkimpy_milter.__init__:main',
        ],
    },
    include_package_data=True,
    data_files=[(os.path.join('share', 'man', 'man5'),
        ['man/dkimpy-milter.conf.5']), (os.path.join('share', 'man', 'man8'),
        ['man/dkimpy-milter.8']), ('etc', ['etc/dkimpy-milter.conf']),
        (os.path.join('lib', 'systemd', 'system'),
        ['system/dkimpy-milter.service']),(os.path.join('etc', 'init.d'),
        ['system/dkimpy-milter']), (os.path.join('etc', 'init.d'),
        ['system/dkimpy-milter.openrc'])],
    zip_safe = False,
    cmdclass={
        'expand': FileMacroExpand,
    },
    **kw
)
