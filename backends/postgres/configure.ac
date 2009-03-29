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
AC_INIT(vpgsql,1.0.0)
AC_CONFIG_HEADER(vpgsql.h)
AC_CANONICAL_HOST

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
# pgconfig
#

AC_MSG_CHECKING(for pgconfig)

pgconfig=""

for f in /usr/local/pgsql/bin/pg_config /usr/local/bin/pg_config /usr/bin/pg_config
do
   if test -x $f; then
	  pgconfig=$f
	  AC_MSG_RESULT($pgconfig)
	  break
   fi
done

if test "$pgconfig" = ""; then
   AC_MSG_RESULT(not found)
   AC_MSG_ERROR([Unable to locate the pg_config program.])
fi

#
# Libraries
#

AC_MSG_CHECKING(linker flags)

auth_libs="-L`$pgconfig --libdir` -lpq "

AC_MSG_RESULT($auth_libs)
AC_SUBST(auth_libs)

#
# Headers
#

AC_MSG_CHECKING(compiler flags)

auth_inc="-I`$pgconfig --includedir`"

AC_MSG_RESULT($auth_inc)
AC_SUBST(auth_inc)

#
# Options
#

AC_MSG_CHECKING(whether to use valias)
AC_ARG_ENABLE(valias,
			  [  --enable-valias         Enable storage of dotqmail data in the PostgreSQL database ],
			  [ 
			    AC_DEFINE_UNQUOTED(VALIAS,1,"")
			    AC_MSG_RESULT(yes)
			  ], AC_MSG_RESULT(no))

#
# Output
#

AC_OUTPUT(Makefile)

echo ""
echo "(Type 'make' to compile)"
echo ""
