# drop_priviledges (from https://github.com/nigelb/Static-UPnP)
# Copyright (C) 2016  NigelB
# Copyright (C) 2018 Scott Kitterman
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


def fold(header):
    """Fold a header line into multiple crlf-separated lines at column 72.
    Borrowed from dkimpy and updated to only add \n instead of \r\n because
    that's what the milter protocol wants.

    >>> text(fold(b'foo'))
    'foo'
    >>> text(fold(b'foo  '+b'foo'*24).splitlines()[0])
    'foo  '
    >>> text(fold(b'foo'*25).splitlines()[-1])
    ' foo'
    >>> len(fold(b'foo'*25).splitlines()[0])
    72
    """
    i = header.rfind(b"\r\n ")
    if i == -1:
        pre = b""
    else:
        i += 3
        pre = header[:i]
        header = header[i:]
    maxleng = 72
    while len(header) > maxleng:
        i = header[:maxleng].rfind(b" ")
        if i == -1:
            j = maxleng
        else:
            j = i + 1
        pre += header[:j] + b"\n   "
        header = header[j:]
    return pre + header


def user_group(userid):
    """Return user and group from UserID"""
    import grp
    import pwd

    userlist = userid.split(':')
    if len(userlist) == 1:
        gidname = userlist[0]
    else:
        gidname = userlist[1]
    # Get the uid/gid from the name
    running_uid = pwd.getpwnam(userlist[0]).pw_uid
    running_gid = grp.getgrnam(gidname).gr_gid
    return running_uid, running_gid


def drop_privileges(milterconfig):
    import os
    import syslog

    if os.getuid() != 0:
        if milterconfig.get('Syslog'):
            syslog.syslog('drop_privileges: Not root. No action taken.')
        return

    # Get user and group
    uid, gid = user_group(milterconfig.get('UserID'))

    # Remove group privileges
    os.setgroups([])

    # Try setting the new uid/gid
    os.setgid(gid)
    os.setuid(uid)

    # Set umask
    old_umask = os.umask(milterconfig.get('UMask'))


class ExceptHook:
    def __init__(self, useSyslog=1, useStderr=0):
        self.useSyslog = useSyslog
        self.useStderr = useStderr

    def __call__(self, etype, evalue, etb):
        import traceback
        import sys
        tb = traceback.format_exception(*(etype, evalue, etb))
        for line in tb:
            if self.useSyslog:
                import syslog
                syslog.syslog(line)
            if self.useStderr:
                sys.stderr.write(line)


def setExceptHook():
    import sys
    sys.excepthook = ExceptHook(useSyslog=1, useStderr=1)


def write_pid(milterconfig):
    """Write PID in pidfile.  Will not overwrite an existing file."""
    import os
    import syslog
    pidfile = milterconfig.get('PidFile')
    if pidfile is None:
        return
    if not os.path.isfile(pidfile):
        pid = str(os.getpid())
        try:
            f = open(pidfile, 'w')
        except IOError as e:
            if str(e)[:35] == '[Errno 2] No such file or directory':
                piddir = pidfile.rsplit('/', 1)[0]
                os.mkdir(piddir)
                user, group = user_group(milterconfig.get('UserID'))
                os.chown(piddir, user, group)
                f = open(pidfile, 'w')
                if milterconfig.get('Syslog'):
                    syslog.syslog('PID dir created: {0}'.format(piddir))
            else:
                if milterconfig.get('Syslog'):
                    syslog.syslog('Unable to write pidfle {0}.  IOError: {1}'
                                  .format(pidfile, e))
                raise
        f.write(pid)
        f.close()
        user, group = user_group(milterconfig.get('UserID'))
        os.chown(pidfile, user, group)
    else:
        if milterconfig.get('Syslog'):
            syslog.syslog('Unable to write pidfle {0}.  File exists.'
                          .format(pidfile))
        raise RuntimeError('Unable to write pidfle {0}.  File exists.'
                           .format(pidfile))
    return pid


def read_keyfile(keyfile, milterconfig):
    """Read private key from file."""
    import syslog
    try:
        f = open(keyfile, 'r')
        keylist = f.readlines()
    except IOError as e:
        if milterconfig.get('Syslog'):
            syslog.syslog('Unable to read keyfile {0}.  IOError: {1}'
                          .format(keyfile, e))
        raise
    f.close()
    key = ''
    for line in keylist:
        key += line
    return key

def read_keytable(tabledict, milterconfig):
    """Read keytables into in memory configuration data so all keys are read
    before priviledges are dropped.
    When loaded, tabeldict is a dict:
        {searchkey: [donamin, selector, key]}
    If key is a file (startswith('/'), then the key is returned in its place."""
    import dkim
    import syslog
    for dictkey, values in tabledict.items():
        if values[-1][:1] == '/' or values[-1][:2] == './' or values[-1][:3] == '../':
            key = read_keyfile(values[-1], milterconfig)
        tabledict[dictkey] = [values[0], values[1], key]
    return tabledict

def get_keys(milterconfig):
    """Read keys (table or file) into memory before dropping priviledges"""
    milterconfig['privateRSA'] = False
    milterconfig['privateRSATable'] = False
    milterconfig['privateEd25519'] = False
    milterconfig['privateEd25519Table'] = False
    if milterconfig.get('KeyTable'):
        milterconfig['privateRSATable'] = read_keytable(milterconfig.get('KeyTable'),
                                                        milterconfig)
    elif milterconfig.get('KeyFile'):
        milterconfig['privateRSA'] = read_keyfile(milterconfig.get('KeyFile'),
                                                  milterconfig)
    if milterconfig.get('KeyTableEd25519'):
        milterconfig['privateEd25519Table'] = read_keytable(milterconfig.get('KeyTableEd25519'),
                                                            milterconfig)
    elif milterconfig.get('KeyFileEd25519'):
        milterconfig['privateEd25519'] = read_keyfile(milterconfig.get('KeyFileEd25519'),
                                                      milterconfig)
    return milterconfig
