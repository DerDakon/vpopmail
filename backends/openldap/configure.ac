#
# $Id$
# Copyright (C) 1999-2009 Inter7 Internet Technologies, Inc.
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
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
#

AC_PREREQ([2.52])
AC_INIT(vopenldap,1.0.0)
AC_CANONICAL_HOST
AC_CONFIG_HEADER(vopenldap.h)

#
# Set default compiler and linker flags
#

AC_SUBST(CFLAGS, "$CFLAGS -I../.. -fPIC")

#
# Programs
#

AC_PROG_CC
AC_PROG_INSTALL
AC_ISC_POSIX

#
# Files
#

AC_MSG_CHECKING(for vpopmail build)

if ! test -r ../module.mk; then
   AC_MSG_RESULT(not found)
   AC_MSG_ERROR(vpopmail is not compiled -- please build the vpopmail source before trying to build modules)
fi

AC_MSG_RESULT(found)

#
# Libraries
#

libdir=""
for f in /usr/local/lib /usr/lib /usr/local/openldap/lib /usr/local/ldap/lib
do
    if test -r $f/libldap.so
    then
        libdir=$f
        break
    fi
done

AC_ARG_ENABLE(libdir,
    [  --enable-libdir=DIR     Your OpenLDAP 'lib' directory.],
    [ 
	  libdir="$enableval"
	  LDFLAGS="$LDFLAGS -L$libdir"
    ]
)

AC_SUBST(libdir)

AC_CHECK_LIB(ldap, ldap_open, [], [ AC_MSG_ERROR(Can't locate LDAP libraries.  Please use --enable-libdir=/path to specify location.) ])
AC_CHECK_LIB(lber, ber_pvt_opt_on, [], [ AC_MSG_ERROR(Can't locate LDAP libraries.  Please use --enable-libdir=/path to specify location.) ])

#
# Headers
#

incdir=""
for f in /usr/local/include /usr/include /usr/local/openldap/include /usr/local/ldap/include
do
    if test -r $f/ldap.h
    then
        incdir=$f
        break
    fi
done

AC_ARG_ENABLE(incdir,
    [  --enable-incdir=DIR     Your OpenLDAP 'include' directory.],
    [ 
	   incdir="$enableval"
	   CFLAGS="$CFLAGS -I$incdir"
    ]
)

AC_SUBST(incdir)

#
# Options
#

#
# IP alias domains
#

AC_MSG_CHECKING(whether ip alias domains is enabled)
AC_ARG_ENABLE(ip-alias-domains,
			  [  --enable-ip-alias-domains         Enable mappings of IPs to domain names ],
			  [ 
			    AC_DEFINE_UNQUOTED(IP_ALIAS_DOMAINS,1,"")
			    AC_MSG_RESULT(yes)
			  ], AC_MSG_RESULT(no))

#
# valias
#

AC_MSG_CHECKING(whether to use valias)
AC_ARG_ENABLE(valias,
			  [  --enable-valias         Enable storage of dotqmail data in the LDAP database ],
			  [ 
			    AC_DEFINE_UNQUOTED(VALIAS,1,"")
			    AC_MSG_RESULT(yes)
			  ], AC_MSG_RESULT(no))

#
# Authentication logging
#

AC_MSG_CHECKING(if authentication logging is enabled)

AC_ARG_ENABLE(auth-logging,
    [  --enable-auth-logging   Enable authentication logging],
	[
	  AC_MSG_RESULT(yes)
	  AC_DEFINE_UNQUOTED(ENABLE_AUTH_LOGGING,1,"")
    ],
	[
	   AC_MSG_RESULT(no)
    ]
)

#
# Output
#

AC_OUTPUT(Makefile)

echo ""
echo "(Type 'make' to compile)"
echo ""
