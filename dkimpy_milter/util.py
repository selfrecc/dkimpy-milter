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


def own_socketfile(milterconfig, sockname=None):
    """If socket is Unix socket, chown to UserID before dropping privileges"""
    import os
    user, group = user_group(milterconfig.get('UserID'))
    offset = None
    if sockname is None:
        sockname = milterconfig.get('Socket')
    if sockname is None:
        return
    if sockname[:1] == '/':
        offset = 0
    elif sockname[:6] == "local:":
        offset = 6
    elif sockname[:5] == "unix:":
        offset = 5

    if offset is not None:
        if os.path.exists(sockname[offset:]):
            os.chown(sockname[offset:], user, group)


def read_keyfile(milterconfig, keytype):
    """Read private key from file."""
    import syslog
    if keytype == "RSA":
        keyfile = milterconfig.get('KeyFile')
    if keytype == "Ed25519":
        keyfile = milterconfig.get('KeyFileEd25519')
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

def read_keytable(milterconfig, tabletype):
    """Read keytables into in memory configuration data so all keys are read
    before priviledges are dropped."""
    import syslog
    if tabletype == "RSA":
        tablefile = milterconfig.get('KeyTable')
    if tabletype == "Ed25519":
        tablefile = milterconfig.get('KeyTableEd25519')
    if milterconfig.get(tablefile):
        keytabledata = []
        try:
            f = open(milterconfig.get(tablefile))
            for row in f:
                keytabledata.append(row) 
            f.close()
        except IOError as e:
            if milterconfig.get('Syslog'):
                syslog.syslog('Unable to read keytable {0}.  IOError: {1}'
                              .format(tablefile, e))
            raise
        
    return keytabledata
