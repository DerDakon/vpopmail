/* 
   $Id: README.pgsql,v 1.11 2004-06-26 01:38:47 tomcollins Exp $
*/
--------------------------------------------------------------------------

Using vpopmail with PostgreSQL is not very common.
The PostgreSQL modules are understood to be functional, but because it not
as popular as using CDB or MySQL auth systems, you should be wary of 
implementing the PostgreSQL system on a production server. 

--------------------------------------------------------------------------

------------------------------------------------------------------------------
2003/Dec/29 : Michael Bowe <mbowe@pipeline.com.au>

A QUICK GUIDE TO VPOPMAIL WITH POSTGRESQL
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Full doc available from :
http://www.pipeline.com.au/staff/mbowe/isp/vpopmail-postgresql.htm

Note :
  You should not permit end-users to have shell access to this server.
  PostgreSQL by default allows any local user to access any database on 
  the server. You can certainly tighten the security of the default 
  PostgreSQL installation, but it is pretty much futile considering that 
  vpopmail stores the PostgresSQL login/pass in the "libvpopmail.a" file. 
  It is straightforward for any knowledgeable local user to be able to 
  extract the user/pass from this file


PostgreSQL:

Setup an account for the PostgreSQL server to run under : 

	useradd postgres

Download and unpack the source

	cd /usr/local/src
	wget ftp://ftp.au.postgresql.org/pub/postgresql/v7.3.4/postgresql-7.3.4.tar.gz
	tar xzf postgresql-7.3.4.tar.gz
	chown -r root.root postgresql-7.3.4
	cd postgresql-7.3.4

Compile source (installs to /usr/local/pgsql)

	./configure
	gmake
	gmake install

Create the data directory

	mkdir /usr/local/pgsql/data
	chown postgres /usr/local/pgsql/data

Run the installation script that creates/verifies all the various
system-use tables etc

	su postgres
	/usr/local/pgsql/bin/initdb -D /usr/local/pgsql/data

Fire up the server

	/usr/local/pgsql/bin/postmaster -D /usr/local/pgsql/data > /usr/local/pgsql/data/serverlog 2>&1 &

At this point the PostgreSQL daemons should be running. A good way
to verify this is to use this command :

	ps axf

If all is well, you should be able to see something like this : 

	388 pts/1 S 0:00 /usr/local/pgsql/bin/postmaster -D /usr/local/pgsql/data
	389 pts/1 S 0:00   \_ postgres: stats buffer process 
	391 pts/1 S 0:00       \_ postgres: stats collector process 

(If you received errors, look in the file /usr/local/pgsql/data/serverlog
for debugging info)

Configure PostgreSQL so it is running all the time from bootup onwards

	# exit back to the root user from the postgres su
	exit
	cp /usr/local/src/postgresql-7.3.4/contrib/start-scripts/linux /etc/rc.d/init.d/postgres
	chmod 744 /etc/rc.d/init.d/postgres
	chkconfig --add postgres

vpopmail:

Make the user accounts

	# If you are using RH8.0, you will probably need to run this following command,
	# because RH8.0 comes preconfigured with UID/GID 89 allocated to postfix
	#
	# userdel postfix

	groupadd -g 89 vchkpw
	useradd -g vchkpw -u 89 vpopmail

	# We recommend you use the user and group id's of 89. The FreeBSD folks
	# have reserved 89 for the group and 89 for the user for vpopmail.  Feel
	# free to have the OS assign the group/user id (for example, Solaris won't 
	# allow gid 89).

Download and unpack the source

	cd /usr/local/src
	wget http://telia.dl.sourceforge.net/sourceforge/vpopmail/vpopmail-5.4.4.tar.gz
	tar xzf vpopmail-5.4.4.tar.gz
	chown -R root.root vpopmail-5.4.4
	cd vpopmail-5.4.4

Create the a vpopmail database in PostgreSQL

	/usr/local/pgsql/bin/createdb --username=postgres --owner=postgres vpopmail

Now, build the program with a configure something like this :

	./configure \
	  --disable-roaming-users \
	  --enable-logging=p \
	  --disable-ip-alias-domains \
	  --disable-passwd \
	  --enable-clear-passwd \
	  --disable-domain-quotas \
	  --enable-auth-module=pgsql \
	  --disable-many-domains \
	  --enable-auth-logging \
	  --enable-pgsql-logging \
	  --enable-valias
 
	make
	make install-strip

------------------------------------------------------------------------------
PREVIOUS VPOPMAIL / PGSQL DOCUMENTATION :

2002/02/22 : N.Fung <nfung@classY.jp>

Notes on translating vmysql.c to vpgsql.c
* strings in SQL statements are enclosed with ' and not ".
* there is no "replace into" in pgsql.
* 'user' is a reserved column name! Changed 'user' to 'userid'.

To get it going become DBA of PostgreSQL server. Then:

1. /path/to/pgsql/bin/createuser vpopmail 
   
   (no need to grant vpopmail dba rights)

2. /path/to/pgsql/bin/createdb vpopmail

If you want to change "vpopmail", make sure you edit vpgsql.h and compile.

---ends---

