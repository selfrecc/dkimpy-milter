#! /usr/bin/python3
# Original dkim-milter.py code:
# Author: Stuart D. Gathman <stuart@bmsi.com>
# Copyright 2007 Business Management Systems, Inc.
# This code is under GPL.  See COPYING for details.

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

import sys
import syslog
import Milter
import dkim
import authres
import os
import tempfile
import io
import re
import codecs
from Milter.utils import parse_addr, parseaddr
import dkimpy_milter.config as config
from dkimpy_milter.util import drop_privileges
from dkimpy_milter.util import setExceptHook
from dkimpy_milter.util import write_pid
from dkimpy_milter.util import get_keys
from dkimpy_milter.util import fold

__version__ = "1.2.0"
FWS = re.compile(r'\r?\n[ \t]+')


class dkimMilter(Milter.Base):
    "Milter to check and sign DKIM.  Each connection gets its own instance."

    def __init__(self):
        self.mailfrom = None
        self.id = Milter.uniqueID()
        # we don't want config used to change during a connection
        self.conf = milterconfig
        self.fp = None
        self.fdomain = ''
        self.iequals = None

    @Milter.noreply
    def connect(self, hostname, unused, hostaddr):
        self.internal_connection = False
        self.external_connection = False
        self.hello_name = None
        # sometimes people put extra space in sendmail config, so we strip
        self.receiver = self.getsymval('j')
        if self.receiver is not None:
            self.receiver = self.receiver.strip()
        try:
            self.AuthservID = self.conf['AuthservID']
        except:
            self.AuthservID = self.receiver
        if hostaddr and len(hostaddr) > 0:
            ipaddr = hostaddr[0]
            if self.conf['IntHosts']:
                if self.conf['IntHosts'].match(ipaddr):
                    self.internal_connection = True
        else:
            ipaddr = ''
        self.connectip = ipaddr
        if self.conf.get('MacroList') and not self.internal_connection:
            macrolist = self.conf.get('MacroList')
            for macro in macrolist:
                macroname = macro.split('|')[0]
                macroname = '{' + macroname + '}'
                macroresult = self.getsymval(macroname)
                if ((len(macro.split('|')) == 1 and macroresult) or macroresult
                        in macro.split('|')[1:]):
                    self.internal_connection = True
        if self.conf.get('MacroListVerify'):
            macrolist = self.conf.get('MacroListVerify')
            for macro in macrolist:
                macroname = macro.split('|')[0]
                macroname = '{' + macroname + '}'
                macroresult = self.getsymval(macroname)
                if ((len(macro.split('|')) == 1 and macroresult) or macroresult
                        in macro.split('|')[1:]):
                    self.external_connection = True
        if self.internal_connection:
            connecttype = 'INTERNAL'
        else:
            connecttype = 'EXTERNAL'
        if self.conf.get('Syslog') and self.conf.get('debugLevel') >= 1:
            syslog.syslog("connect from {0} at {1} {2}"
                          .format(hostname, hostaddr, connecttype))
        return Milter.CONTINUE

    # multiple messages can be received on a single connection
    # envfrom (MAIL FROM in the SMTP protocol) seems to mark the start
    # of each message.
    @Milter.noreply
    def envfrom(self, f, *str):
        if self.conf.get('Syslog') and self.conf.get('debugLevel') >= 2:
            syslog.syslog("mail from: {0} {1}".format(f, str))
        self.fp = io.BytesIO()
        self.mailfrom = f
        t = parse_addr(f)
        if len(t) == 2:
            t[1] = t[1].lower()
        self.canon_from = '@'.join(t)
        self.has_dkim = 0
        self.author = None
        self.arheaders = []
        self.arresults = []
        return Milter.CONTINUE

    @Milter.noreply
    def header(self, name, val):
        lname = name.lower()
        if self.conf.get('Syslog') and self.conf.get('debugLevel') >= 4:
            if lname == 'content-transfer-encoding':
                syslog.syslog("content-transfer-encodeing: {0}".format(val))
            if lname == 'content-type':
                syslog.syslog("content-type: {0}".format(val))
        if lname == 'dkim-signature':
            if (self.conf.get('Syslog') and
                    self.conf.get('debugLevel') >= 1):
                syslog.syslog("{0}: {1}".format(name, val))
            self.has_dkim += 1
        if lname == 'from':
            fname, self.author = parseaddr(val)
            try:
                self.fdomain = self.author.split('@')[1].lower()
            except IndexError as er:
                pass # self.author was not a proper email address
            if (self.conf.get('Syslog') and
                    self.conf.get('debugLevel') >= 1):
                syslog.syslog("{0}: {1}".format(name, val))
        elif lname == 'authentication-results':
            self.arheaders.append(val)
        if self.fp:
            try:
                self.fp.write(b"%s: %s\n" % (codecs.encode(name, 'ascii'), codecs.encode(val, 'ascii')))
            except:
                # Don't choke on header fields with non-ascii garbage in them.
                pass
        return Milter.CONTINUE

    @Milter.noreply
    def eoh(self):
        if self.fp:
            self.fp.write(b"\n")   # terminate headers
        self.bodysize = 0
        return Milter.CONTINUE

    @Milter.noreply
    def body(self, chunk):        # copy body to temp file
        if self.fp:
            self.fp.write(chunk)  # IOError causes TEMPFAIL in milter
            self.bodysize += len(chunk)
        return Milter.CONTINUE

    def eom(self):
        if not self.fp:
            return Milter.ACCEPT  # no message collected - so no eom processing
        # Remove existing Authentication-Results headers for our authserv_id
        for i, val in enumerate(self.arheaders, 1):
            # FIXME: don't delete A-R headers from trusted MTAs
            try:
                ar = (authres.AuthenticationResultsHeader
                      .parse_value(FWS.sub('', val)))
                if ar.authserv_id == self.AuthservID:
                    self.chgheader('authentication-results', i, '')
                    if (self.conf.get('Syslog') and
                            self.conf.get('debugLevel') >= 1):
                        syslog.syslog('REMOVE: {0}'.format(val))
            except:
                # Don't error out on unparseable AR header fiels
                pass
        # Check and/or sign DKIM
        if (self.conf.get('Syslog') and self.conf.get('debugLevel') >= 4):
            syslog.syslog('self.conf: {0}'.format(self.conf))
        self.fp.seek(0)
        txt = self.fp.read()
        self.get_identities_sign()
        if (self.conf.get('Syslog') and self.conf.get('debugLevel') >= 3):
            syslog.syslog('self.domain: {0}, self.fdomain: {1}, self.iequals: {2}'.format(self.domain, self.fdomain, self.iequals))
        if ((self.fdomain in self.domain) and not self.conf.get('Mode') == 'v'
                and not self.external_connection):
            self.sign_dkim(txt)
        if ((self.has_dkim) and (not self.internal_connection) and
            (self.conf.get('Mode') == 'v' or
             self.conf.get('Mode') == 'sv')):
            self.check_dkim(txt)
        if self.arresults:
            h = authres.AuthenticationResultsHeader(authserv_id=
                                                    self.AuthservID,
                                                    results=self.arresults)
            h = fold(codecs.encode(str(h), 'ascii'))
            if (self.conf.get('Syslog') and
                    self.conf.get('debugLevel') >= 2):
                syslog.syslog(codecs.decode(h, 'ascii'))
            name, val = codecs.decode(h, 'ascii').split(': ', 1)
            self.addheader(name, val, 0)
        return Milter.CONTINUE

    # get parent domain to be signed for if fdomain is a subdomain
    def get_parent_domain(self, fdomain, domains):
        for domain in domains:
            rhs = '.'+domain
            # compare right hand side of fdomain against .domain
            if fdomain[-len(rhs):] == rhs:
                # return parent domain on match
                syslog.syslog('domain: {0}'.format(domain))
                return domain
        # or return the fdomain itself
        return fdomain

    def get_identities_sign(self):
        """Determine d= and i= identiies for signature"""
        self.domain = []
        iequals = None
        try:
            self.privkeyRSA = self.conf.get('privateRSA')
        except:
            self.privkeyRSA = ''
        try:
            self.privkeyEd25519 = self.conf.get('privateEd25519')
        except:
            self.privkeyEd25519 = ''
        try:
            self.selectorRSA = self.conf.get('Selector')
        except:
            self.selectorRSA = ''
        try:
            self.selectorEd25519 = self.conf.get('SelectorEd25519')
        except:
            self.selectorEd25519 = ''
        if not self.domain and self.conf.get('Domain'):
            self.domain = self.conf.get('Domain')
        if self.conf.get('SubDomains'):
            self.fdomain = self.get_parent_domain(self.fdomain, self.domain)
        if self.conf.get('SigningTable'):
            match = False
            for dictkey, dictvalues in self.conf.get('SigningTable').items():
                if dictkey == '%':
                    self.domain.append(self.fdomain)
                    match = True
                elif len(dictkey.split('*')) == 1:
                    if dictkey == self.author:
                        self.domain.append(self.fdomain)
                        match = True
                else:
                    if len(dictkey.split('*')) == 2:
                        if dictkey.split('*')[1] == self.author[-len(dictkey.split('*')[1]):]:
                            self.domain.append(self.fdomain)
                            match = True
                    self.domain.append(self.fdomain)
                try:
                    if len(dictvalues) == 2 and match:
                        if dictvalues[0] =='%':
                            self.iequals = codecs.encode('@' + self.fdomain)
                        elif dictvalues[0][1:] == self.fdomain or self.get_parent_domain(dictvalues[0][1:], self.domain) == self.fdomain:
                            self.iequals = codecs.encode(dictvalues[0])
                except IndexError:
                    pass
                if match:
                    #TODO add KeyTable stuffs here.
                    keytablekey = dictvalues[-1] # Last value in the SigningTable row.
                    if self.conf.get('privateRSATable'):
                        # Table data is a list of [ signing domain, selector, key ]
                        keytabledata = self.conf.get('privateRSATable')[keytablekey]
                        try:
                            self.fdomain = keytabledata[0]
                            self.selectorRSA = keytabledata[1]
                            self.privkeyRSA = keytabledata[2]
                        except:
                            if (self.conf.get('Syslog')):
                                    syslog.syslog('Error: Invalid KeyTable data {0}'.format(keytabledata))
                    if self.conf.get('privateEd25519Table'):
                        # Table data is a list of [ signing domain, selector, key ]
                        keytabledata = self.conf.get('privateEd25519Table')[keytablekey]
                        try:
                            self.fdomain = keytabledata[0]
                            self.selectorEd25519 = keytabledata[1]
                            self.privkeyEd25519 = keytabledata[2]
                        except:
                            if (self.conf.get('Syslog')):
                                    syslog.syslog('Error: Invalid KeyTable data {0}'.format(keytabledata))
                    break

    def sign_dkim(self, txt):
        canon = codecs.encode(self.conf.get('Canonicalization'), 'ascii')
        canonicalize = []
        if len(canon.split(b'/')) == 2:
            canonicalize.append(canon.split(b'/')[0])
            canonicalize.append(canon.split(b'/')[1])
        else:
            canonicalize.append(canon)
            canonicalize.append(canon)
            if (self.conf.get('Syslog') and
                    self.conf.get('debugLevel') >= 1):
                syslog.syslog('canonicalize: {0}'.format(canonicalize))
        sign_headers = self.conf.get('SignHeaders')
        if not sign_headers:
            # None or empty. DKIM explicitly tests for None.
            sign_headers = None
        try:
            if self.privkeyRSA:
                d = dkim.DKIM(txt)
                h = d.sign(codecs.encode(self.selectorRSA, 'ascii'), codecs.encode(self.fdomain, 'ascii'),
                           codecs.encode(self.privkeyRSA, 'ascii'),
                           canonicalize=(canonicalize[0], canonicalize[1]),
                           identity=self.iequals, include_headers=sign_headers)
                name, val = h.split(b': ', 1)
                self.addheader(codecs.decode(name, 'ascii'), codecs.decode(val, 'ascii').strip().replace('\r\n', '\n'), 0)
                if (self.conf.get('Syslog') and
                    (self.conf.get('SyslogSuccess')
                     or self.conf.get('debugLevel') >= 1)):
                    syslog.syslog('{0}: {1} DKIM signature added (s={2} '
                                  'd={3})'.format(self.getsymval('i'),
                                                  d.signature_fields.get(b'a').decode(),
                                                  d.signature_fields.get(b's').decode(),
                                                  d.domain.decode().lower()))
            if self.privkeyEd25519:
                d = dkim.DKIM(txt)
                h = d.sign(codecs.encode(self.selectorEd25519, 'ascii'), codecs.encode(self.fdomain, 'ascii'),
                           self.privkeyEd25519,
                           canonicalize=(canonicalize[0], canonicalize[1]),
                           identity=self.iequals, include_headers=sign_headers,
                           signature_algorithm=b'ed25519-sha256')
                name, val = h.split(b': ', 1)
                self.addheader(codecs.decode(name, 'ascii'), codecs.decode(val, 'ascii').strip().replace('\r\n', '\n'), 0)
                if (self.conf.get('Syslog') and
                    (self.conf.get('SyslogSuccess')
                     or self.conf.get('debugLevel') >= 1)):
                    syslog.syslog('{0}: {1} DKIM signature added (s={2} '
                                  'd={3})'.format(self.getsymval('i'),
                                                  d.signature_fields.get(b'a').decode(),
                                                  d.signature_fields.get(b's').decode(),
                                                  d.domain.decode().lower()))
        except dkim.DKIMException as x:
            if self.conf.get('Syslog'):
                syslog.syslog('DKIM: {0}'.format(x))
        except Exception as x:
            if self.conf.get('Syslog'):
                syslog.syslog("sign_dkim: {0}".format(x))
            raise

    def check_dkim(self, txt):
        res = False
        self.header_a = None
        for y in range(self.has_dkim):  # Verify _ALL_ the signatures
            d = dkim.DKIM(txt, minkey=self.conf.get('MinimumKeyBits'), timeout=self.conf.get('DNSTimeout'))
            try:
                dnsoverride = self.conf.get('DNSOverride')
                if isinstance(dnsoverride, str):
                    timeout = 5
                    domain = self.fdomain
                    def dnsfunc(domain, timeout=timeout, dnsoverride=dnsoverride):
                        return dnsoverride
                    syslog.syslog("DNSOverride: {0}".format(dnsoverride))
                    res = d.verify(idx=y, dnsfunc=dnsfunc)
                else:
                    res = d.verify(idx=y)
                algo = codecs.decode(d.signature_fields.get(b'a'), 'ascii')
                if res:
                    if algo == 'ed25519-sha256':
                        self.dkim_comment = ('Good {0} signature'
                                             .format(algo))
                    else:
                        self.dkim_comment = ('Good {0} bit {1} signature'
                                             .format(d.keysize, algo))
                else:
                    self.dkim_comment = ('Bad {0} bit {1} signature.'
                                         .format(d.keysize, algo))
            except dkim.DKIMException as x:
                self.dkim_comment = str(x)
                if self.conf.get('Syslog'):
                    syslog.syslog('DKIM: {0}'.format(x))
            except Exception as x:
                self.dkim_comment = str(x)
                if self.conf.get('Syslog'):
                    syslog.syslog("check_dkim: Internal program fault while verifying: {0}".format(x))
            try:
                # i= is optional and dkimpy is fine if it's not provided
                self.header_i = codecs.decode(d.signature_fields.get(b'i'), 'ascii')
            except TypeError as x:
                self.header_i = None
            try:
                self.header_d = codecs.decode(d.signature_fields.get(b'd'), 'ascii')
                self.header_a = codecs.decode(d.signature_fields.get(b'a'), 'ascii')
            except Exception as x:
                self.dkim_comment = str(x)
                if self.conf.get('Syslog'):
                    syslog.syslog("check_dkim: Internal program fault extracting header a or d: {0}".format(x))
                self.header_d = None
            if not self.header_a:
                self.header_a = 'rsa-sha256'
            if res:
                if (self.conf.get('Syslog') and
                        (self.conf.get('SyslogSuccess') or
                         self.conf.get('debugLevel') >= 1)):
                    syslog.syslog('{0}: {1} DKIM signature verified (s={2} '
                                  'd={3})'.format(self.getsymval('i'),
                                                  d.signature_fields.get(b'a').decode(),
                                                  d.signature_fields.get(b's').decode(),
                                                  d.domain.decode().lower()))
                self.dkim_domain = d.domain.lower()
            else:
                if self.conf.get('DiagnosticDirectory'):
                    tempfile.tempdir = self.conf.get('DiagnosticDirectory')
                    fd, fname = tempfile.mkstemp(".dkim")
                    with os.fdopen(fd, "w+b") as fp:
                        fp.write(txt)
                    if self.conf.get('Syslog'):
                        syslog.syslog('DKIM: Fail (saved as {0})'
                                      .format(fname))
                else:
                    if self.conf.get('Syslog'):
                        if d.domain:
                            syslog.syslog('DKIM: Fail ({0})'
                                          .format(d.domain.lower()))
                        else:
                            syslog.syslog('DKIM: Fail, unextractable domain')
            if res:
                result = 'pass'
            else:
                result = 'fail'
            res = False
            if self.header_d:
                self.arresults.append(
                    authres.DKIMAuthenticationResult(result=result,
                                                 header_i=self.header_i,
                                                 header_d=self.header_d,
                                                 header_a=self.header_a,
                                                 result_comment=
                                                 self.dkim_comment)
            )
            self.header_a = None
        return

def main():
    # Ugh, but there's no easy way around this.
    global milterconfig
    configFile = '/usr/local/etc/dkimpy-milter.conf'
    if len(sys.argv) > 1:
        if (sys.argv[1] in ('-?', '--help', '-h')) or len(sys.argv) == 3 or \
               (len(sys.argv) == 4 and sys.argv[2] != '-P'):
            print('usage: dkimpy-milter [<configfilename> [-P <pidfile>]]')
            sys.exit(1)
        configFile = sys.argv[1]
    milterconfig = config._processConfigFile(filename=configFile)
    if len(sys.argv) == 4:
        if sys.argv[2] == '-P':
            # Command line PID file argument overrides config file
            milterconfig['PidFile'] = sys.argv[3]
    if milterconfig.get('Syslog'):
        facility = eval("syslog.LOG_{0}"
                        .format(milterconfig.get('SyslogFacility').upper()))
        syslog.openlog(os.path.basename(sys.argv[0]), syslog.LOG_PID, facility)
        setExceptHook()
    pid = write_pid(milterconfig)
    milterconfig = get_keys(milterconfig)
    Milter.factory = dkimMilter
    Milter.set_flags(Milter.CHGHDRS + Milter.ADDHDRS)
    miltername = 'dkimpy-filter'
    socketname = milterconfig.get('Socket')
    if socketname is None:
        if int(os.environ.get('LISTEN_PID', '0')) == os.getpid():
            lfds = os.environ.get('LISTEN_FDS')
            if lfds is not None:
                if lfds != '1':
                    syslog.syslog('LISTEN_FDS is set to "{0}", but we only know how to deal with "1", ignoring it'.
                                  format(lfds))
                else:
                    socketname = 'fd:3'
        if socketname is None:
            socketname = 'local:/var/run/dkimpy-milter/dkimpy-milter.sock'
    sys.stdout.flush()
    if milterconfig.get('Syslog'):
        syslog.syslog('dkimpy-milter starting:{0} user:{1}'
                      .format(pid, milterconfig.get('UserID')))
    drop_privileges(milterconfig)
    Milter.runmilter(miltername, socketname, 240)

if __name__ == "__main__":
    main()
