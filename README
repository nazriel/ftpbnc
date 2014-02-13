README for f-ftpbnc-v1.6

This is a fully functional ftp port "bouncer" for glftpd and compatible
ftp-daemons. It is written from scratch and uses a special state-machine driven
structure. The current version has following key features:

 o Running in a single process. No forking (except for daemonizing), so no
   endless process tree and all sockets are treated in non-blocking mode.

 o Very fast and very small: activates many TCP accelerations and requires
   less than 8096 bytes ram per forwarded connection.

 o Supports ident requesting and passing on to glftpd as IDNT.
   This can also be disabled and so makes the bnc a pure port forwarder.

 o AUTH SSL compatible. (does not touch passed data in any way)

 o No logging of connections, ips, traffic to log files. Only in debug mode
   will it show ips.

 o Hammer protection based on multiple connects from the same ip.

 o Encrypts config data within the program image: two methods available.
   Either the decryption key is stored in the binary, or it has to be supplied
   by the user when starting the bnc.

 o Optionally changes the proc line shown in ps to indicate the current number
   of bounced connections.

 o Compiles fine under Linux, FreeBSD, OpenBSD. Others may need a little
   porting.

--- Installation ---

Compilation is easily done with:
"make"

You will be asked for the configuration options, and if all goes well you have
an f-ftpbnc binary at the end. Then start up the bnc with "./f-ftpbnc".

!!! Remember to rm the inc-config.h once you are sure everything works fine.
    It contains you configuration (though not in plain-text). Best is to cp the
    f-ftpbnc binary into a different dir and rm the whole source.

--- Forum ----

If you require additional help please visit the new support forum at

http://www.high-society.at/forum/

--- Features ---

Some of the key features need further explanation:

The ftpbnc runs in a single process with a main select()-driven loop, and
processes each socket with a state-machine. This approach goes easier on system
resources than the fork() after accept approach of most other ftp-bncs.

It is AUTH SSL/TLS compatible, which means that it doesn't modify any forwarded
data. In particular it does not implement SSL itself, that is the ftp daemons
part. Therefore it cannot work as a traffic/data bouncer as it cannot read the
ftp statements inside the encrypted ssl-stream (this also prevents sniffing of
the ftp-control-stream on the bncbox).

The bnc features a fast and primitive hammer protection against hammering from
one ip by limiting the number of accepted connections over a period of
time. For more info see the config tool.

Encrypting the configuration data of the ftp bouncer is widely regarded as a
great improvement of security. f-ftpbnc tries to give you all possible
encryption variants:

The configuration data block of f-ftpbnc is _always_ compiled into the binary,
which means it does not have a bnc.conf or similar lying around. So if you run
multiple bncs from one dir, you have to create multiple binaries (f-bnc1,
f-bnc2, ...). 

f-ftpbnc uses the xTEA encryption cipher in CBC mode to encrypt the
configuration block inside the binary image. To decrypt it when the bnc starts
up, it requires the encryption password/key. There are two methods available:
a) Save the encryption key in the binary image.
   This enables the bnc to start up by-itself (e.g. from cron). But this also
   reduces the encryption to a mere hiding or scrambling of the config data.
   Someone trying to find out what the bnc does, need only trace it with a
   debugger or mere strace ./f-ftpbnc will show where it connects to.
b) Do not include the encryption key in the binary.
   When the bnc is started it will require you to enter the correct encryption
   key or it cannot start up. This means the config data in the binary is
   truly unreadable without the key, which you should keep somewhere safe.
   But mark that the bnc can then _not_ be started by cron.

Have Fun
F

$Rev: 421 $ $Date: 2008-01-30 22:56:40 +0100 (Wed, 30 Jan 2008) $

Changes:
v1.6
- fixed critical bug in buffering of client commands before IDNT

v1.5
- added support for disabling ident lookup
- now uses non-blocking write
- and fixed ident timeouts for filtered ident ports

v1.1
- freebsd problems
- making valgrind happy
- added proctitle support
