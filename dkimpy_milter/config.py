# -*- coding: utf-8 -*-
#
#  Tumgreyspf
#  Copyright © 2004-2005, Sean Reifschneider, tummy.com, ltd.
#
#  pypolicyd-spf changes
#  Copyright © 2007,2008,2009,2010 Scott Kitterman <scott@kitterman.com>
#
#  dkimpy-milter changes
#  Copyright © 2018 Scott Kitterman <scott@kitterman.com>
#  Note: Derived from pypolicydspfsupp.py version before relicensing to Apache
#        2.0 license - 100% GPL
'''
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as published 
    by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.'''

import syslog
import os
import sys
import re
import urllib
import stat
import dkim


#  default values
defaultConfigData = {
        'Syslog' : 'yes',
        'SyslogFacility' : 'mail',
        'UMask' : 007,
        'Mode' : 'sv',
        'Socket' : 'local:/var/run/dkimpy-milter/dkimpy-milter.sock',
        'PidFile'  : '/var/run/dkimpy-milter/dkimpy-milter.pid',
        'UserID' : 'dkimpy-milter',
        'Canonicalization' : 'relaxed/simple'
        }


#################################
class ConfigException(Exception):
    '''Exception raised when there's a configuration file error.'''
    pass

####################################################################
def _processConfigFile(filename = None, configdata = None, useSyslog = 1,
        useStderr = 0):
    '''Load the specified config file, exit and log errors if it fails,
    otherwise return a config dictionary.'''

    import config
    if configdata == None: configdata = config.defaultConfigData
    if filename != None:
        try:
            _readConfigFile(filename, configdata)
        except Exception, e:
            raise
            if useSyslog:
                syslog.syslog(e.args[0])
            if useStderr:
                sys.stderr.write('%s\n' % e.args[0])
            sys.exit(1)
    return(configdata)

####################
def _find_boolean(item):
    if type(item) == int:
        item = str(item)
    if item[0] in ["T", "t", "Y", "y", "1"]:
        item = True
    elif item[0] in ["F", "f", "N", "n", "0"]:
        item = False
    else:
        raise dkim.ParameterError()
    return item


def _dataset_to_list(dataset):
    """Convert a dataset (as defined in dkimpymilter.8) and return a python
       list of values."""
    if not isinstance(dataset, str):
        # If it was a csl with more than one value, it's already a list, we
        # only need to remove the name from the first value.
        if dataset[0][:4] == 'csl:':
            dataset[0] = dataset[0][4:]
        for item in dataset:
            dataset[dataset.index(item)] = item.strip().strip(',')
        return dataset
    elif isinstance(dataset, str):
        if dataset[0] == '/' or dataset[:5] == 'file:':
            # This is a flat file dataset
            ds = []
            if dataset[0] == '/':
                dsname = dataset
            if dataset[:5] == 'file:':
                dsname = dataset[5:]
            dsf = open(dsname, 'r')
            for line in dsf.readlines():
                if line[0] != '#':
                    if len(line.split(':')) == 1:
                        ds.append(line.strip())
                    else:
                        for element in line.split(':'):
                            ds.append(element.strip().strip(':'))
            dsf.close()
            return ds
        # If it's a str and csl, it has one value and we return a list
        if dataset[:4] == 'csl:':
            return [dataset[4:].strip().strip(',')]
        else:
            return [dataset.strip().strip(',')]
            
    raise dkim.ParameterError('Unimplmented dataset type: {0}'.format(type(dataset)))

###############################################################
commentRx = re.compile(r'^(.*)#.*$')
def _readConfigFile(path, configData = None, configGlobal = {}):
    '''Reads a configuration file from the specified path, merging it
    with the configuration data specified in configData.  Returns a
    dictionary of name/value pairs based on configData and the values
    read from path.'''

    debugLevel = configGlobal.get('debugLevel', 0)
    if debugLevel >= 5: syslog.syslog('readConfigFile: Loading "%s"' % path)
    if configData == None: configData = {}
    nameConversion = {
        'AuthservID' : 'str',
        'Syslog' : 'bool',
        'SyslogFacility' : 'str',
        'SyslogSuccess' : 'bool',
        'UMask' : 'int',
        'Mode' : 'str',
        'Socket' : 'str',
        'PidFile'  : 'str',
        'UserID' : 'str',
        'Domain' : 'dataset',
        'KeyFile' : 'str',
        'KeyFileEd25519' : 'str',
        'Selector' : 'str',
        'SelectorEd25519': 'str',
        'Canonicalization' : 'str',
            }

    #  check to see if it's a file
    try:
        mode = os.stat(path)[0]
    except OSError, e:
        syslog.syslog(syslog.LOG_ERR,'ERROR stating "%s": %s' % ( path, e.strerror ))
        return(configData)
    if not stat.S_ISREG(mode):
        syslog.syslog(syslog.LOG_ERR,'ERROR: is not a file: "%s", mode=%s' % ( path, oct(mode) ))
        return(configData)

    #  load file
    fp = open(path, 'r')
    while 1:
        line = fp.readline()
        if not line: break

        #  parse line
        line = line.split('#', 1)[0].strip()
        if not line: continue
        data = line.split()
        if len(data) != 2:
            if len(data) == 1:
                if debugLevel >= 1:
                    syslog.syslog('Configuration item "%s" not defined in file "%s"'
                        % ( line, path ))
        if len(data) == 1:
            name = data
            value = ''
        if len(data) == 2:
            name, value = data
        if len(data) >= 3:
            name = data[0]
            value = data[1:]

        #  check validity of name
        conversion = nameConversion.get(name)
        if conversion == None:
            syslog.syslog('ERROR: Unknown name "%s" in file "%s"' % ( name, path ))
            continue

        if debugLevel >= 5: syslog.syslog('readConfigFile: Found entry "%s=%s"'
                % ( name, value ))
        if conversion == 'bool':
            configData[name] = _find_boolean(value)
        elif conversion == 'str':
            configData[name] = str(value)
        elif conversion == 'int':
            configData[name] = int(value)
        elif conversion == 'dataset':
            configData[name] = _dataset_to_list(value)
        else:
            syslog.syslog(str('name: ' + name + ' value: ' + value + ' conversion: ' + conversion))
            configData[name] = conversion(value)
    fp.close()
    
    return(configData)
