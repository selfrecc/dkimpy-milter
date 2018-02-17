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

def drop_privileges(milterconfig):
    import os
    import grp
    import pwd
    import syslog

    if os.getuid() != 0:
        if milterconfig.get('Syslog'):
            syslog.syslog('drop_privileges: Not running as root. Cannot drop permissions.')
        return

    # Figure out if user and group are specified
    userstr = milterconfig.get('UserID')
    userlist = userstr.split(':')
    if len(userlist) == 1:
        gidname = userlist[0]
    else:
        gidname = userlist[1]
    uidname = userlist[0]

    # Get the uid/gid from the name
    running_uid = pwd.getpwnam(uidname).pw_uid
    running_gid = grp.getgrnam(gidname).gr_gid

    # Remove group privileges
    os.setgroups([])

    # Try setting the new uid/gid
    os.setgid(running_gid)
    os.setuid(running_uid)

    # Set umask
    old_umask = os.umask(milterconfig.get('UMask'))

#################
class ExceptHook:
    def __init__(self, useSyslog = 1, useStderr = 0):
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


####################
def setExceptHook():
    import sys
    sys.excepthook = ExceptHook(useSyslog = 1, useStderr = 1)

####################
def write_pid(milterconfig):
    """Write PID in pidfile.  Will not overwrite an existing file."""
    import os
    import syslog
    if not os.path.isfile(milterconfig.get('PidFile')):
        pid = str(os.getpid())
        try:
            f = open(milterconfig.get('PidFile'), 'w')
        except IOError as e:
            if milterconfig.get('Syslog'):
                syslog.syslog('Unable to write pidfle {0}.  IOError: {1}'.format(milterconfig.get('PidFile'), e))
            raise
        f.write(pid)
        f.close()
    else:
        if milterconfig.get('Syslog'):
            syslog.syslog('Unable to write pidfle {0}.  File exists.'.format(milterconfig.get('PidFile')))
        raise RuntimeError('Unable to write pidfle {0}.  File exists.'.format(milterconfig.get('PidFile')))

####################
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
            syslog.syslog('Unable to read keyfile {0}.  IOError: {1}'.format(keyfile, e))
        raise
    f.close()
    key = ''
    for line in keylist:
        key += line
    return key
