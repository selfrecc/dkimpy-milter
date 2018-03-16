#! /usr/bin/python
# dkimpy-milter: A DKIM signing/verification Milter application
# Author: Scott Kitterman <scott@kitterman.com>
# Copyright 2018 Scott Kitterman
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
import os

description = "Domain Keys Identified Mail (DKIM) signing/verifying milter for Postfix/Sendmail."

kw = {}  # Work-around for lack of 'or' requires in setuptools.
try:
    import DNS
    kw['install_requires'] = ['dkimpy>=0.7', 'pymilter', 'authres>=1.1.0', 'PyNaCl', 'ipaddress', 'PyDNS']
except ImportError:  # If PyDNS is not installed, prefer dnspython
    kw['install_requires'] = ['dkimpy>=0.7', 'pymilter', 'authres>=1.1.0', 'PyNaCl', 'ipaddress', 'dnspython']

setup(
    name='dkimpy-milter',
    version='0.9.7',
    author='Scott Kitterman',
    author_email='scott@kitterman.com',
    url='https://launchpad.net/dkimpy-milter',
    description=description,
    download_url = "https://pypi.python.org/pypi/dkimpy-milter",
    classifiers= [
        'Development Status :: 4 - Beta',
        'Environment :: No Input/Output (Daemon)',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Natural Language :: English',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 2 :: Only',
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
        ['system/dkimpy-milter'])],
    zip_safe = False,
    **kw
)
