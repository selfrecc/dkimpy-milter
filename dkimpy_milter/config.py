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
import stat
import dkim
import socket
import ipaddress
from dnsplug import Session

#  default values
defaultConfigData = {
    'Syslog': 'yes',
    'SyslogFacility': 'mail',
    'UMask': 007,
    'Mode': 'sv',
    'Socket': 'local:/var/run/dkimpy-milter/dkimpy-milter.sock',
    'PidFile': '/var/run/dkimpy-milter/dkimpy-milter.pid',
    'UserID': 'dkimpy-milter',
    'Canonicalization': 'relaxed/simple',
    'InternalHosts': '127.0.0.1',
    'IntHosts': False,
    'DiagnosticDirectory': '',
    'MacroList': '',
    'MacroListVerify': '',
    'debugLevel': 0  # Undocumented config item for developer use
    }


class ConfigException(Exception):
    '''Exception raised when there's a configuration file error.'''
    pass


class HostsDataset(object):
    '''Hold a group of host related dataset objects'''

    def __init__(self, dataset):
        self.dataset = []
        # Self.dataset will end up being a list of DataSetItem(s).
        for item in dataset:
            item = item.rstrip(']')
            item = item.lstrip('[')
            self.dataset.append(self.DatasetItem(item))

    class DatasetItem(object):
        '''Individual dataset item'''

        def __init__(self, item):
            self.item = item
            self.isipv4 = False
            self.isipv4cidr = False
            self.isipv6 = False
            self.isipv6cidr = False
            self.ishostname = False
            self.isdomain = False
            self.negative = False
            if self.item[0] == '!':
                self.item = item[1:]
                self.negative = True
            try:
                self.item = ipaddress.ip_address(unicode(self.item, "utf-8"))
                if isinstance(self.item, ipaddress.IPv4Address):
                    self.isipv4 = True
                elif isinstance(self.item, ipaddress.IPv6Address):
                    self.isipv6 = True
            except ValueError as e:
                try:
                    self.item = ipaddress.ip_network(unicode
                                                     (self.item, "utf-8"),
                                                     strict=False)
                    if isinstance(self.item, ipaddress.IPv4Network):
                        self.isipv4cidr = True
                    elif isinstance(self.item, ipaddress.IPv6Network):
                        self.isipv6cidr = True
                except ValueError as e2:
                    if self.item[0] == '.' and len(self.item.split('.')) > 2:
                        self.isdomain = True
                    elif len(self.item.split('.')) > 1:  # It has a '.' in it
                        self.ishostname = True
                    else:
                        raise ConfigException('Unknown dataset item: {0}'
                                              .format(item))

    def match(self, connectip):
        '''Check if the connect IP is part of the dataset'''
        source = ipaddress.ip_address(unicode(connectip, "utf-8"))
        for item in self.dataset:
            if item.isdomain or item.ishostname:
                result = self.matchname(source)   # Match host/domains first
                if result:
                    return(result)
            elif item.isipv4 or item.isipv4cidr:  # Then IPv4/6 addresses or
                if isinstance(source, ipaddress.IPv4Address):  # networks
                    return(self.match4(source))   # depending on the item type
            elif item.isipv6 or item.isipv6cidr:  # and connect type
                if isinstance(source, ipaddress.IPv6Address):
                    return(self.match6(source))

    def matchname(self, source):
        '''Does source IP address relate to a domain/hostname in the dataset'''
        match = False
        matchone = False
        negativeone = False
        matchdomain = False
        negativedomain = False
        ptrlist = self.getptr(source)
        for item in self.dataset:
            if item.isdomain:
                for ptr in ptrlist:
                    # Strip the leading '.' off the domain name for exact match
                    if item.item[1:] == ptr[-len(item.item)+1:]:
                        matchdomain = True
                        negativedomain = item.negative
            elif item.ishostname:
                for ptr in ptrlist:
                    if item.item == ptr:
                        matchone = True
                        negativeone = item.negative
        if matchdomain and not negativedomain:
            match = True
        if matchone and not negativeone:
            return True
        if matchone and negativeone:
            match = False
        return(match)

    def getptr(self, source):
        '''Get validated PTR name of IP address'''
        results = []
        s = Session()
        ptrnames = s.dns(source.reverse_pointer, 'PTR')
        for name in ptrnames:
            if isinstance(source, ipaddress.IPv4Address):
                ips = s.dns(name, 'A')
                for ip in ips:
                    ip = ipaddress.IPv4Address(unicode(ip, 'UTF-8'))
                    if ip == source:
                        results.append(name)
            if isinstance(source, ipaddress.IPv6Address):
                ips = s.dns(name, 'AAAA')
                for ip in ips:
                    ip = ipaddress.IPv6Address(unicode(ip, 'UTF-8'))
                if ip == source:
                    results.append(name)
        return results

    def match4(self, source):
        '''Is the source IP related to a IPv4 address/network in the dataset'''
        match = False
        matchone = False
        negativeone = False
        matchcidr = False
        negativecidr = False
        for item in self.dataset:
            if item.isipv4:
                if source == item.item:
                    matchone = True
                    negativeone = item.negative
            elif item.isipv4cidr:
                if source in item.item:
                    matchcidr = True
                    negativecidr = item.negative
        if matchcidr and not negativecidr:
            match = True
        if matchone and not negativeone:
            return True
        if matchone and negativeone:
            match = False
        return(match)

    def match6(self, source):
        '''Is the source IP realted to a IPv6 address/network in the dataset'''
        match = False
        matchone = False
        negativeone = False
        matchcidr = False
        negativecidr = False
        for item in self.dataset:
            if item.isipv6:
                if source == item.item:
                    matchone = True
                    negativeone = item.negative
            elif item.isipv6cidr:
                if source in item.item:
                    matchcidr = True
                    negativecidr = item.negative
        if matchcidr and not negativecidr:
            match = True
        if matchone and not negativeone:
            return True
        if matchone and negativeone:
            match = False
        return(match)


def _processConfigFile(filename=None, configdata=None, useSyslog=1,
                       useStderr=0):
    '''Load the specified config file, exit and log errors if it fails,
    otherwise return a config dictionary.'''

    import config
    if configdata is None:
        configdata = config.defaultConfigData
    if filename is not None:
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


def _make_authserv_id(as_id):
    """Determine AuthservID if needed"""
    if as_id == 'HOSTNAME':
        as_id = socket.gethostname()
    return as_id


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
        if dataset[-3:] == '.db' or dataset[:3] == 'db:':
            #  This is a Sleepycat (Oracle) DB  dataset
            import whichdb  # Will need rewriting someday for python3
            if dataset[-3:] == '.db':
                dbname = dataset
            elif dataset[:3] == 'db:':
                dbname = dataset[3:]
            else:
                raise dkim.ParameterError('Unimplmented dataset type: {0}'
                                          .format(type(dataset)))
            if whichdb.whichdb(dbname) != 'dbhash':
                raise dkim.ParameterError('Unimplmented dataset type: {0}'
                                          .format(type(dataset)))
            #TODO replace this with code to use db maps
            raise dkim.ParameterError('Unsupported dataset db datase: {0}'
                                      .format(type(dataset)))

    raise dkim.ParameterError('Unimplmented dataset type: {0}'
                              .format(type(dataset)))


def _readConfigFile(path, configData=None, configGlobal={}):
    '''Reads a configuration file from the specified path, merging it
    with the configuration data specified in configData.  Returns a
    dictionary of name/value pairs based on configData and the values
    read from path.'''

    debugLevel = configGlobal.get('debugLevel', 0)
    if debugLevel >= 5:
        syslog.syslog('readConfigFile: Loading "%s"' % path)
    if configData is None:
        configData = {}
    nameConversion = {
        'AuthservID': 'str',
        'Syslog': 'bool',
        'SyslogFacility': 'str',
        'SyslogSuccess': 'bool',
        'UMask': 'int',
        'Mode': 'str',
        'Socket': 'str',
        'PidFile': 'str',
        'UserID': 'str',
        'Domain': 'dataset',
        'KeyFile': 'str',
        'KeyFileEd25519': 'str',
        'Selector': 'str',
        'SelectorEd25519': 'str',
        'Canonicalization': 'str',
        'InternalHosts': 'dataset',
        'IntHosts': 'bool',
        'DiagnosticDirectory': 'str',
        'MacroList': 'dataset',
        'MacroListVerify': 'dataset',
        'debugLevel': 'int'
        }

    #  check to see if it's a file
    try:
        mode = os.stat(path)[0]
    except OSError, e:
        syslog.syslog(syslog.LOG_ERR, 'ERROR stating "%s": %s'
                      % (path, e.strerror))
        return(configData)
    if not stat.S_ISREG(mode):
        syslog.syslog(syslog.LOG_ERR, 'ERROR: is not a file: "%s", mode=%s'
                      % (path, oct(mode)))
        return(configData)

    #  load file
    fp = open(path, 'r')
    while 1:
        line = fp.readline()
        if not line:
            break

        #  parse line
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        data = line.split()
        if len(data) != 2:
            if len(data) == 1:
                if debugLevel >= 1:
                    syslog.syslog('Config item "%s" not defined in file "%s"'
                                  % (line, path))
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
        if conversion is None:
            syslog.syslog('ERROR: Unknown name "%s" in file "%s"'
                          % (name, path))
            continue

        if debugLevel >= 5:
            syslog.syslog('readConfigFile: Found entry "%s=%s"'
                          % (name, value))
        if conversion == 'bool':
            configData[name] = _find_boolean(value)
        elif conversion == 'str':
            configData[name] = str(value)
        elif conversion == 'int':
            configData[name] = int(value)
        elif conversion == 'dataset':
            configData[name] = _dataset_to_list(value)
        else:
            syslog.syslog(str('name: ' + name + ' value: ' + value +
                              ' conversion: ' + conversion))
            configData[name] = conversion(value)
    fp.close()
    try:
        configData['AuthservID'] = _make_authserv_id(configData['AuthservID'])
        configData['IntHosts'] = HostsDataset(configData['InternalHosts'])
    except:
        pass

    return(configData)
