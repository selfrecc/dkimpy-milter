# OVERVIEW

This is a DKIM signing and verification milter.  It has been tested with both
Postfix and Sendmail.

The configuration file is designed to be compatible with OpenDKIM, but only
a subset of OpenDKIM options are supported.  If an unsupported option is
specified, an error will be raised.


# INSTALLATION

This package includes a default configuration file and man pages.  For those
to be installed when installing using setup.py, the following incantation is
required because setuptools developers decided not being able to do this by
default is a feature:

[sudo] python3 setup.py install --single-version-externally-managed --record=/dev/null

For users of Debian Stable (Debian 9, Codename Squeeze), all dependencies are
available in either the main or backports repositories:

[sudo] apt install python3-milter python3-nacl python3-dnspython
[sudo] apt install -t stretch-backports python3-authres python3-dkim

It is also available in the Debian package archive:

[sudo] apt install dkimpy-milter [Debian 10 or later]
[sudo] apt install -t stretch-backports dkimpy-milter [Debian 9]

When installing using the Debian package, all dependencies are automatically
installed.

The preferred method of installation is from PyPi using pip (if distribution
packages are not available):

[sudo] pip install dkimpy_milter

Using pip will cause required packages to be installed via easy_install if they
have not been previously installed.  Because pymilter and PyNaCl are compiled
Python extensions, the system will need appropriate development packages and
an C compiler.  Alternately, install these dependencies from distribution/OS
packages and then pip install dkimpy_milter.

The milter will work with either py3dns (DNS) or dnspython (dns), preferring
dnspython if both are available.  The dkimpy DKIM module also works with
either.

## NON-STANDARD INSTALLATION PATHS

The package includes a custom setup command called expand.  It allows various
file locations in init scripts, man pages, and config files to be over-ridden
at install time.


    expand: Expand @@ variables in input files, simlar to make macros.
    user_options:
      --sysconfigdir=, e: Specify system configuration directory.
      --sbindir=, s: Specify system binary directory [not used].
      --bindir=, b: Specify binary directory.
      --rundir=,r: Specify run state directory.

As an example, to change the run directory to /var/run, one would do:

    python3 setup.py expand --rundir=/var/run
    [sudo] python3 setup.py install --single-version-externally-managed \
                                --record=/dev/null

or in a single step (the order matters):

    [sudo] python3 setup.py expand --rundir=/var/run install \
                               --single-version-externally-managed \
                               --record=/dev/null

# SETUP

## SIGNING KEYS

In order to create DKIM signatures, a private key must be available.  Signing
keys should be protected (owned by root:root with permissions 600 in a
directory that is not world readable).  Different keys are required for RSA
and (if used) Ed25519.

### RSA

Both public and private keys for RSA have standard formats and there are many
tools available to create them.  Keys must (RFC 8302) have a minimum size of
1024 bits and should have a size of at least 2048 bits.  The dknewkey script
that is provided with dkimpy is one such tool:

    dknewkey exampleprivkey

will produce both the private key file (.key suffix) and a file with the DKIM
public key record to be published DNS (.dns suffix).  RSA is the default key
type.  2048 bits is the default key size.

### ED25519

There is no standardized non-binary representation for Ed25519 private keys,
so in order to generate Ed25519 keys for dkimpy-milter, dkimpy specific tools
must be used to be compatible.  The same dknewkey script support Ed25519:

    dknewkey --ktype ed25519 anothernewkey

will provide both the private key file (.key suffix) and a file with the DKIM
public key record to be published DNS (.dns suffix).  Ed25519 keys do not have
variable bit lengths.

### COMPLEX SIGNING CONFIGURATIONS

The KeyTable, KeyTableEd25519, and SigningTable are used to define signing
instructions to the filter where use of Domain, Selector and KeyFile together
are insufficient.

First, select the type of database you will use for each.  They need not
be the same.  The "DATA SETS" portion of the dkimpy-milter(8) man page
describes the possibilities and how they are formatted.  Then, construct those
databases.

Let's suppose you want to sign for two domains, example.com and example.net.
Within example.com, you want to sign for user "president" differently than
everyone else.  Let's say further that you want to use a flat text file.

You've generated private key files for each of these and stored them
in the directory /usr/local/etc/dkim/keys as files "president", "excom" and
"exnet", with the obvious intents.  You want to use selectors "foo", "bar"
and "baz" for those, respectively.  The signing domains match the senders
(i.e. the signatures for example.com's stuff will be held by example.com,
and example.net likewise).

First, write the KeyTable.  This is a list of the keys you intend to use,
and you just assign arbitrary names to them.  So as a flat file, the KeyTable
for the above might look like this:

	preskey	example.com:foo:/usr/local/etc/dkim/keys/president
	comkey	example.com:bar:/usr/local/etc/dkim/keys/excom
	netkey	example.net:baz:/usr/local/etc/dkim/keys/exnet

If also signing with ed25519, specify a KeyTableEd25519, with the same
names, pointing to the keys needed for ed25519.  Both KeyTable and
KeyTableEd25519 are evaluated if there is a SigningTable (see below).

Per the documentation, multi-field data sets that are made of flat files have
the fields separated by colons, but the key and value(s) are separated by
whitespace.

So now we've named each key file, and specified with which selector and domain
each will be used, and then given each of those groupings a name.  This
is your KeyTable.  Let's say you put it in /usr/local/etc/dkim/keytable.

Next, write the SigningTable.  This maps senders (by default, taken from the
From: header field of a message passing through the filter) to which keys
will be used to sign their mail.  Wildcards are allowed.  So to do what was
described above, we write it as follows:

	president@example.com	preskey
	*@example.com		comkey
	*@example.net		netkey

Since we want to use wildcards, we can't actually use a regular flat file.
Wildcards require a regular expression file, or "refile".  The above is
valid format for one of those.  Let's say you put this in
/usr/local/etc/dkim/signingtable.

Finally, tell the filter that it should use these files by adding this to
your configuration file:

	KeyTable	/usr/local/etc/dkim/keytable
	SigningTable	refile:/usr/local/etc/dkim/signingtable

You could put "file:" in front of the filename for the KeyTable just to be
precise, but "file:" is assumed if the value starts with a "/".

Note: Unlike opendkim, dkimpy-milter will check for "\*" in the signing table
regardless of if refile is specified or not.  Use of refile is supported for
compatibility with configurations initially developed for use with opendkim.

## MTA INTEGRATION

Both a systemd unit file and a sysv init file are provided.  Both make
assumptions about defaults being used, e.g. if a non-standard pidfile name is
used, they will need to be updated.  The sysv init file uses start-stop-deamon
from Debian.  It is not portable to systems without that available.

The dkimpy-milter drops priviledges after setup to the user/group specified in
UserID.  During initial setup, this system user needs to be manually created.
As an example, using the default dkimpy-user on Debian, the command would be:

    [sudo] adduser --system --no-create-home --quiet --disabled-password \
               --disabled-login --shell /bin/false --group \
               --home /run/dkimpy-milter dkimpy-milter

Since /var/run or /run is sometimes on a tempfs, if the PID file directory is
missing, the milter will create it on startup.

To start dkimpy-milter with systemd for the first time, you will need to take
the following steps:

    [sudo] systemctl daemon-reload
    [sudo] systemctl enable dkimpy-milter
    [sudo] systemctl start dkimpy-milter
    [sudo] systemctl status dkimpy-milter (to verify it started correctly)

As with all milters, dkimpy-milter needs to be integrated with your MTA of
choice (Sendmail or Postfix).  When integrating with your MTA, the risk of
signature invalidation due to content conversion of the message body needs to
be considered.  See RFC 6376, Section 5.3 for discussion of this issue.  As a
practical matter, when signing, configure the milter to follow all others that
might modify the message body.  When verifying, configure the milter before
other processes that might modify the message body.

### SENDMAIL

Configuration is very similar to opendkim, but needs some adjustment for
dkimpy-milter. Here's an example configuration line to include in your
sendmail.mc:

    INPUT_MAIL_FILTER(`dkimpy-milter', `S=local:/run/dkimpy-milter/dkimpy-milter.sock')dnl

Changing the sendmail.mc file requires a Make (to compile it into sendmail.cf)
and a restart of sendmail.  Note that S= needs to match the value of Socket in
the dkimpy-milter configuration file.

Milter support should be present by default in most versions of sendmail
these days, but if not included in your Sendmail build, see:
http://www.elandsys.com/resources/sendmail/milter.html

#### ISSUES USING SENDMAIL TO SIGN AND VERIFY

When using the sendmail MTA in both signing and verifying mode, there are
a few issues of which to be aware that might cause operational problems
and deserve consideration.

(a) When the MTA will be used for relaying emails, e.g. delivering to other
    hosts using the aliases mechanism, it is important not to break
    signatures inserted by the original sender.  This is particularly sensitive
    particular when the sending domain has published a "reject" DMARC policy.

    By default, sendmail quotes to address header fields when there are no
    quotes and the display part of the address contains a period or an
    apostrophe.  However, dkimpy-milter only sees the raw, unmodified form of
    the header field, and so the content that gets verified and what gets
    signed will not be the same, guaranteeing the attached signature is not
    valid.

    To direct sendmail not to modify the headers, add this to your sendmail.mc:

    	conf(`confMUST_QUOTE_CHARS', `')

(b) As stated in sendmail's KNOWNBUGS file, sendmail truncates header field
    values longer than 256 characters, which could mean truncating the domain
    of a long From: header field value and invalidating the signature.
    You may wish to consider increasing MAXNAME in sendmail/conf.h to mitigate
    changing the messages and invalidating their signatures.  This change
    requires recompiling sendmail.

(c) Similar to (a) above, sendmail may wrap very long single-line recipient
    fields for presentation purposes; for example:

    To: very long name <a@example.org>,anotherloo...ong name b <b@example.org>

    ...might be rewritten as:

    To: very long name <a@example.org>,
    	anotherloo...ong name b <b@example.org>

    This rewrite is also done after dkimpy-milter has seen the message,
    meaning the signature dkimpy-milter attaches to the message does not match
    the content it signed.  There is not a known configuration change to
    mitigate this mutation.

    The only known mechanism for dealing with this is to have distinct
    instances of dkimpy-milter do the verifying (inbound) and signing
    (outbound) so that the version that arrives at the signing instance is
    already in the rewritten form, guaranteeing the input and output are the
    same and thus the signature matches the payload.

### POSTFIX

Integration of dkimpy-milter into Postfix is like any milter (See Postfix's
README_FILES/MILTER_README).  Here's an example master.cf excerpt that talks
to two dkimpy-milter instances, one configured for signing and one configured
for verification:

    smtp       inet  n       -       -       -      -       smtpd
        ...
        -o smtpd_milters=inet:localhost:8892
        ...

    submission inet  n       -       -       -      -       smtpd
        ...
        -o smtpd_milters=inet:localhost:8891
        ...

These need to match the Socket value for each dkimpy-milter instance.

Care is required to segregate outbound mail to be signed and inbound mail to
be verified.  The above example uses two instances of dkimpy-milter to do
this.  There are many possible ways.  Here is another example using milter
macros to keep the mail streams segregated:

Postfix master.cf:

    smtp       inet  n       -       -       -       -       smtpd
        ...
        -o smtpd_milters=inet:localhost:8891
        -o milter_macro_daemon_name=VERIFYING
        ...

    submission inet n       -       -       -       -       smtpd
        -o syslog_name=postfix/submission
        -o smtpd_tls_security_level=encrypt
        -o smtpd_sasl_auth_enable=yes
        ...
        -o milter_macro_daemon_name=ORIGINATING
        -o smtpd_milters=inet:localhost:8891
        ...

Dkimpy-milter.conf:

    ...
    Mode			sv
    MacroList		dameon_name|ORIGINATING
    MacroListVerify		daemon_name|VERIFYING
    ...


# NOTES

The python DKIM library, dkimpy, requires the entire message being signed or
verified to be in memory, so dkimpy-milter does not write messages out to a
temp file.  This may impact performance on low-memory systems.

DKIM with Ed25519 signatures are described in RFC 8463.  Version 1.0.0 and
later support Ed25519 signing and verification.  RFC 8301 removed rsa-sha1
from DKIM.  dkimpy-milter does not sign with rsa-sha1, but still considers
rsa-sha1 signatures as valid for verification because they are still in
common use and are not known to be cryptographically broken.
