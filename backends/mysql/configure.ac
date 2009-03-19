#
# $Id: configure.ac 820 2009-03-14 20:34:30Z volz0r $
# Copyright (C) 1999-2009 Inter7 Internet Technologies, Inc.
#

AC_PREREQ([2.52])
AC_INIT(vcdb,1.0.0)
AC_CANONICAL_HOST

#
# Set default compiler and linker flags
#

AC_SUBST(CFLAGS, "-I../.. -I../../cdb -fPIC")
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

AC_CHECK_LIB(m, floor)
AC_CHECK_LIB(z, compress)
AC_CHECK_LIB(mysqlclient, mysql_real_connect)

libdir=""
for f in /usr/local/mysql/lib/mysql /usr/local/mysql/lib  /usr/local/lib/mysql /usr/lib/mysql
do
    if test -d $f
    then
        libdir=$f
        break
    fi
done

AC_ARG_ENABLE(libdir,
    [  --enable-libdir=DIR        Your MySQL 'lib' directory.],
    libdir="$enableval",
)

AC_SUBST(libdir)

#
# Headers
#

incdir=""
for f in /usr/local/mysql/include/mysql /usr/local/mysql/include /usr/local/include/mysql /usr/include/mysql
do
    if test -d $f
    then
        incdir=$f
        break
    fi
done

AC_ARG_ENABLE(incdir,
    [  --enable-incdir=DIR        Your MySQL 'include' directory.],
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
