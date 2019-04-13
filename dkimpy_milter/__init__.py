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
from dkimpy_milter.util import read_keyfile
from dkimpy_milter.util import own_socketfile
from dkimpy_milter.util import fold

__version__ = "1.0.1"
FWS = re.compile(r'\r?\n[ \t]+')


class dkimMilter(Milter.Base):
    "Milter to check and sign DKIM.  Each connection gets its own instance."

    def __init__(self):
        self.mailfrom = None
        self.id = Milter.uniqueID()
        # we don't want config used to change during a connection
        self.conf = milterconfig
        self.privatersa = privateRSA
        self.privateed25519 = privateEd25519
        self.fp = None

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
            self.AuthservID = milterconfig['AuthservID']
        except:
            self.AuthservID = self.receiver
        if hostaddr and len(hostaddr) > 0:
            ipaddr = hostaddr[0]
            if milterconfig['IntHosts']:
                if milterconfig['IntHosts'].match(ipaddr):
                    self.internal_connection = True
        else:
            ipaddr = ''
        self.connectip = ipaddr
        if milterconfig.get('MacroList') and not self.internal_connection:
            macrolist = milterconfig.get('MacroList')
            for macro in macrolist:
                macroname = macro.split('|')[0]
                macroname = '{' + macroname + '}'
                macroresult = self.getsymval(macroname)
                if ((len(macro.split('|')) == 1 and macroresult) or macroresult
                        in macro.split('|')[1:]):
                    self.internal_connection = True
        if milterconfig.get('MacroListVerify'):
            macrolist = milterconfig.get('MacroListVerify')
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
        if milterconfig.get('Syslog') and milterconfig.get('debugLevel') >= 1:
            syslog.syslog("connect from {0} at {1} {2}"
                          .format(hostname, hostaddr, connecttype))
        return Milter.CONTINUE

    # multiple messages can be received on a single connection
    # envfrom (MAIL FROM in the SMTP protocol) seems to mark the start
    # of each message.
    @Milter.noreply
    def envfrom(self, f, *str):
        if milterconfig.get('Syslog') and milterconfig.get('debugLevel') >= 2:
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
        if lname == 'dkim-signature':
            if (milterconfig.get('Syslog') and
                    milterconfig.get('debugLevel') >= 1):
                syslog.syslog("{0}: {1}".format(name, val))
            self.has_dkim += 1
        if lname == 'from':
            fname, self.author = parseaddr(val)
            try:
                self.fdomain = self.author.split('@')[1].lower()
            except IndexError as er:
                self.fdomain = ''  # self.author was not a proper email address
            if (milterconfig.get('Syslog') and
                    milterconfig.get('debugLevel') >= 1):
                syslog.syslog("{0}: {1}".format(name, val))
        elif lname == 'authentication-results':
            self.arheaders.append(val)
        if self.fp:
            self.fp.write(b"%s: %s\n" % (codecs.encode(name, 'ascii'), codecs.encode(val, 'ascii')))
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
                    if (milterconfig.get('Syslog') and
                            milterconfig.get('debugLevel') >= 1):
                        syslog.syslog('REMOVE: {0}'.format(val))
            except:
                # Don't error out on unparseable AR header fiels
                pass
        # Check or sign DKIM
        self.fp.seek(0)
        if milterconfig.get('Domain'):
            domain = milterconfig.get('Domain')
        else:
            domain = ''
        if milterconfig.get('SubDomains'):
            self.fdomain = _get_parent_domain(self.fdomain, domain)
        if ((self.fdomain in domain) and not milterconfig.get('Mode') == 'v'
                and not self.external_connection):
            txt = self.fp.read()
            self.sign_dkim(txt)
        if ((self.has_dkim) and (not self.internal_connection) and
            (milterconfig.get('Mode') == 'v' or
             milterconfig.get('Mode') == 'sv')):
            txt = self.fp.read()
            self.check_dkim(txt)
        if self.arresults:
            h = authres.AuthenticationResultsHeader(authserv_id=
                                                    self.AuthservID,
                                                    results=self.arresults)
            h = fold(codecs.encode(str(h), 'ascii'))
            if (milterconfig.get('Syslog') and
                    milterconfig.get('debugLevel') >= 2):
                syslog.syslog(codecs.decode(h, 'ascii'))
            name, val = codecs.decode(h, 'ascii').split(': ', 1)
            self.addheader(name, val, 0)
        return Milter.CONTINUE

    def sign_dkim(self, txt):
        canon = codecs.encode(milterconfig.get('Canonicalization'), 'ascii')
        canonicalize = []
        if len(canon.split(b'/')) == 2:
            canonicalize.append(canon.split(b'/')[0])
            canonicalize.append(canon.split(b'/')[1])
        else:
            canonicalize.append(canon)
            canonicalize.append(canon)
            if (milterconfig.get('Syslog') and
                    milterconfig.get('debugLevel') >= 1):
                syslog.syslog('canonicalize: {0}'.format(canonicalize))
        try:
            if privateRSA:
                d = dkim.DKIM(txt)
                h = d.sign(codecs.encode(milterconfig.get('Selector'), 'ascii'), codecs.encode(self.fdomain, 'ascii'),
                           codecs.encode(privateRSA, 'ascii'),
                           canonicalize=(canonicalize[0],
                                         canonicalize[1]))
                name, val = h.split(b': ', 1)
                self.addheader(codecs.decode(name, 'ascii'), codecs.decode(val, 'ascii').strip().replace('\r\n', '\n'), 0)
                if (milterconfig.get('Syslog') and
                    (milterconfig.get('SyslogSuccess')
                     or milterconfig.get('debugLevel') >= 1)):
                    syslog.syslog('{0}: {1} DKIM signature added (s={2} '
                                  'd={3})'.format(self.getsymval('i'),
                                                  d.signature_fields.get(b'a').decode(),
                                                  d.signature_fields.get(b's').decode(),
                                                  d.domain.decode().lower()))
            if privateEd25519:
                d = dkim.DKIM(txt)
                h = d.sign(codecs.encode(milterconfig.get('SelectorEd25519'), 'ascii'), codecs.encode(self.fdomain, 'ascii'),
                           privateEd25519, canonicalize=(canonicalize[0],
                                                         canonicalize[1]),
                           signature_algorithm=b'ed25519-sha256')
                name, val = h.split(b': ', 1)
                self.addheader(codecs.decode(name, 'ascii'), codecs.decode(val, 'ascii').strip().replace('\r\n', '\n'), 0)
                if (milterconfig.get('Syslog') and
                    (milterconfig.get('SyslogSuccess')
                     or milterconfig.get('debugLevel') >= 1)):
                    syslog.syslog('{0}: {1} DKIM signature added (s={2} '
                                  'd={3})'.format(self.getsymval('i'),
                                                  d.signature_fields.get(b'a').decode(),
                                                  d.signature_fields.get(b's').decode(),
                                                  d.domain.decode().lower()))
        except dkim.DKIMException as x:
            if milterconfig.get('Syslog'):
                syslog.syslog('DKIM: {0}'.format(x))
        except Exception as x:
            if milterconfig.get('Syslog'):
                syslog.syslog("sign_dkim: {0}".format(x))
            raise

    def check_dkim(self, txt):
        res = False
        for y in range(self.has_dkim):  # Verify _ALL_ the signatures
            d = dkim.DKIM(txt)
            try:
                dnsoverride = milterconfig.get('DNSOverride')
                if isinstance(dnsoverride, str):
                    syslog.syslog("DNSOverride: {0}".format(dnsoverride))
                    res = d.verify(idx=y, dnsfunc=lambda _x: dnsoverride)
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
                if milterconfig.get('Syslog'):
                    syslog.syslog('DKIM: {0}'.format(x))
            except Exception as x:
                self.dkim_comment = str(x)
                if milterconfig.get('Syslog'):
                    syslog.syslog("check_dkim: {0}".format(x))
            self.header_i = codecs.decode(d.signature_fields.get(b'i'), 'ascii')
            self.header_d = codecs.decode(d.signature_fields.get(b'd'), 'ascii')
            self.header_a = codecs.decode(d.signature_fields.get(b'a'), 'ascii')
            if res:
                if (milterconfig.get('Syslog') and
                        (milterconfig.get('SyslogSuccess') or
                         milterconfig.get('debugLevel') >= 1)):
                    syslog.syslog('{0}: {1} DKIM signature verified (s={2} '
                                  'd={3})'.format(self.getsymval('i'),
                                                  d.signature_fields.get(b'a').decode(),
                                                  d.signature_fields.get(b's').decode(),
                                                  d.domain.decode().lower()))
                self.dkim_domain = d.domain.lower()
            else:
                if milterconfig.get('DiagnosticDirectory'):
                    fd, fname = tempfile.mkstemp(".dkim")
                    with os.fdopen(fd, "w+b") as fp:
                        fp.write(txt)
                    if milterconfig.get('Syslog'):
                        syslog.syslog('DKIM: Fail (saved as {0})'
                                      .format(fname))
                else:
                    syslog.syslog('DKIM: Fail ({0})'.format(d.domain.lower()))
            if res:
                result = 'pass'
            else:
                result = 'fail'
            res = False
            self.arresults.append(
                authres.DKIMAuthenticationResult(result=result,
                                                 header_i=self.header_i,
                                                 header_d=self.header_d,
                                                 header_a=self.header_a,
                                                 result_comment=
                                                 self.dkim_comment)
            )
        return

# get parent domain to be signed for if fdomain is a subdomain
def _get_parent_domain(fdomain, domains):
    for domain in domains:
        rhs = '.'+domain
        # compare right hand side of fdomain against .domain
        if fdomain[-len(rhs):] == rhs:
            # return parent domain on match
            return domain
    # or return the fdomain itself
    return fdomain

def main():
    # Ugh, but there's no easy way around this.
    global milterconfig
    global privateRSA
    global privateEd25519
    privateRSA = False
    privateEd25519 = False
    configFile = '/usr/local/etc/dkimpy-milter.conf'
    if len(sys.argv) > 1:
        if sys.argv[1] in ('-?', '--help', '-h'):
            print('usage: dkimpy-milter [<configfilename>]')
            sys.exit(1)
        configFile = sys.argv[1]
    milterconfig = config._processConfigFile(filename=configFile)
    if milterconfig.get('Syslog'):
        facility = eval("syslog.LOG_{0}"
                        .format(milterconfig.get('SyslogFacility').upper()))
        syslog.openlog(os.path.basename(sys.argv[0]), syslog.LOG_PID, facility)
        setExceptHook()
    pid = write_pid(milterconfig)
    if milterconfig.get('KeyFile'):
        privateRSA = read_keyfile(milterconfig, 'RSA')
    if milterconfig.get('KeyFileEd25519'):
        privateEd25519 = read_keyfile(milterconfig, 'Ed25519')
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
    own_socketfile(milterconfig, socketname)
    drop_privileges(milterconfig)
    sys.stdout.flush()
    Milter.runmilter(miltername, socketname, 240)
    if milterconfig.get('Syslog'):
        syslog.syslog('dkimpy-milter started:{0} user:{1}'
                      .format(pid, milterconfig.get('UserID')))

if __name__ == "__main__":
    main()
