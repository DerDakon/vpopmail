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
AC_INIT(vcdb,1.0.0)
AC_CANONICAL_HOST
AC_CONFIG_HEADER(vcdb.h)

#
# Set default compiler and linker flags
#

AC_SUBST(CFLAGS, "$CFLAGS -I../.. -I../../cdb -fPIC")

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
