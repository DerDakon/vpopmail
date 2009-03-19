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
AC_INIT(vldap,1.0.0)
AC_CANONICAL_HOST

#
# Set default compiler and linker flags
#

AC_SUBST(CFLAGS, "-I../.. -fPIC")
AC_SUBST(LDFLAGS, "")

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

#
# I'm unsure of what to test for
#

AC_CHECK_LIB(ldap, ldap_open)
AC_CHECK_LIB(lber, ber_pvt_opt_on)

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
    [  --enable-libdir=DIR        Your OpenLDAP 'lib' directory.],
    libdir="$enableval",
)

AC_SUBST(libdir)

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
    [  --enable-incdir=DIR        Your OpenLDAP 'include' directory.],
    incdir="$enableval",
)

AC_SUBST(incdir)

#
# Output
#

AC_OUTPUT(Makefile)

echo ""
echo "(Type 'make' to compile)"
echo ""
