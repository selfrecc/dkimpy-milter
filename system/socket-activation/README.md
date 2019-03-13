This directory contains example systemd unit files for running a
supervised, socket-activated instance of dkimpy-milter.

There are several advantages of using socket activation:

- dkimpy-milter never runs with elevated privileges, they are dropped
  before any dkimpy-milter code is executed.
   
- The socket is opened before dkimpy-milter runs.  This means that
  clients can connect() to the socket immediately.  So even if there
  is a delay in dkimpy-milter startup, or in libmilter itself, the
  connection will not fail.
  
- You can set the privileges of a listening Unix-domain socket by an
  override of ListenGroup= in dkimpy-milter.socket (see
  systemd.unit(5) for how to override).  This lets you control who has
  access to the daemon with finer granularity than is available with
  dkimpy-milter on its own.
  
- dkimpy-milter will not consume system resources if it is not used.

- A fully-supervised dkimpy-milter needs no PIDFile, UMask, UserID, or
  Socket configuation.  This eliminates common race conditions and
  startup failures, and simplifies the resulting configuration file.
  
There is one downside to using socket activation:

- it will only work on systems where libmilter can support connection
  strings like "fd:3".  This has been supported on Debian and derived
  systems since sendmail 8.14.4-6 (before Debian Jessie, in early
  2014), see for example:
  https://sources.debian.org/src/sendmail/8.15.2-8/debian/patches/socket_activation.patch/
