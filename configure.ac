#
# $Id$
# Copyright (C) 1999-2009 Inter7 Internet Technologies, Inc.
#

AC_PREREQ([2.52])
AC_INIT(vpopmail,5.5.0)
AC_CANONICAL_HOST
AC_CONFIG_HEADER(config.h)

#
# Default CFLAGS
#

if test -z "$CFLAGS"
then
   AC_SUBST(CFLAGS, "")
fi

#
# Default LDFLAGS
#

if test -z "$LDFLAGS"
then
   AC_SUBST(LDFLAGS, "")
fi

#
# Export package version
#

AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE_NAME", "")
AC_DEFINE_UNQUOTED(VERSION, "$VERSION_VERSION", "")

#
# Programs
#

AC_PROG_AWK
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_RANLIB
AC_ISC_POSIX

#
# Libraries
#

AC_CHECK_LIB(crypt, crypt)
AC_CHECK_LIB(dl, dlopen)

#
# Headers
#

AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h assert.h byteswap.h crypt.h ctype.h dirent.h endian.h err.h errno.h fcntl.h memory.h netinet/in.h pwd.h shadow.h signal.h stdarg.h stdint.h stdio.h stdlib.h string.h strings.h sys/file.h syslog.h sys/param.h sys/socket.h sys/stat.h sys/time.h sys/types.h sys/uio.h sys/un.h sys/wait.h time.h unistd.h utime.h dlfcn.h])

#
# Compiler language support
#

AC_C_CONST
AC_C_INLINE

#
# Type definitions
#

AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SIGNAL
AC_STRUCT_TM

#
# Functions
#

AC_FUNC_CHOWN
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STAT
AC_FUNC_UTIME_NULL
AC_CHECK_FUNCS([bzero dup2 fdatasync getcwd gethostname getpass getspnam memset mkdir putenv rmdir socket strchr strdup strerror strncasecmp strrchr strspn strstr utime warn chdir umask strtok strchr strstr close execv write read fopen fputs atoi atol malloc memset strcmp strncmp strcasecmp waitpid strncat strcpy fflush kill rename chmod free srand rand getenv gmtime strtoll])

#
# Operating system specific settings
#

#
# id command
#

AC_MSG_CHECKING(id command syntax)

case "$host" in
  *-*-sunos4.1.1*)
    idcommand="/usr/xpg4/bin/id -u"
    ;;
  *-*-solaris2.8*)
    idcommand="/usr/xpg4/bin/id -u"
    ;;
  *-*-solaris*)
    idcommand="/usr/xpg4/bin/id -u"
    ;;
  *)
    idcommand="id -u"
    ;;
esac

AC_MSG_RESULT($idcommand)

#
# ps command
#

AC_MSG_CHECKING(ps command syntax)

case "$host" in
  *-*-sunos4.1.1*)
        PS_COMMAND="ps -aux"
    ;;
  *-*-solaris*)
        PS_COMMAND="ps -ef"
    ;;
  *-*-sunos*)
        PS_COMMAND="ps -ef"
    ;;
  *-sgi-5*)
        PS_COMMAND="ps -ef"
    ;;
  *-ibm-aix*)
        PS_COMMAND="ps -ef"
    ;;
  mips-dec-mach3*)
        PS_COMMAND="ps -ef"
    ;;
  *-dec-ultrix*)
        PS_COMMAND="ps -ef"
    ;;
  *-*-hpux*)
        PS_COMMAND="ps -eaf"
    ;;
  alpha-dec-osf*)
        PS_COMMAND="ps -ef"
    ;;
  *-*-nextstep*)
        PS_COMMAND="ps -ef"
    ;;
  i*86-*-bsdi*)
        PS_COMMAND="ps axww"
    ;;
  i*86-unknown-bsd*)
        PS_COMMAND="ps -ef"
    ;;
  m68k-sony-newsos*)
        PS_COMMAND="ps -ef"
    ;;
  mips-sony-bsd*)
        PS_COMMAND="ps -ef"
    ;;
  m68k-apple-aux*)
        PS_COMMAND="ps -ef"
    ;;
  m88k-dg-dgux*)
        PS_COMMAND="ps -ef"
    ;;
  t3e-*-*)
        PS_COMMAND="ps -ef"
    ;;
  *-cray-unicos*)
        PS_COMMAND="ps -ef"
    ;;
  *-*-sysv4*)
        PS_COMMAND="ps -ef"
    ;;
  *-*-machten*)
        PS_COMMAND="ps -ef"
    ;;
  i*86-unknown-sco*)
        PS_COMMAND="ps -ef"
    ;;
  *-convex-bsd*)
        PS_COMMAND="ps -ef"
    ;;
  *-sequent-ptx*)
        PS_COMMAND="ps -ef"
    ;;
  *-sequent-dynix*|*-sequent-ptx*)
        PS_COMMAND="ps -ef"
    ;;
  *-*-freebsd*)
        PS_COMMAND="ps aux"
    ;;
  *-*-netbsd*)
        PS_COMMAND="ps aux"
    ;;
  *-*-openbsd*)
        PS_COMMAND="ps -aux"
    ;;
  *-*-IRIX*)
        PS_COMMAND="ps -ef"
    ;;
  *)
        PS_COMMAND="ps axww"
    ;;
esac

AC_DEFINE_UNQUOTED(PS_COMMAND,"$PS_COMMAND","")
AC_MSG_RESULT($PS_COMMAND)

#
# Solaris system requires extra libraries
#

# XXX TODO extralibflags should just set LDFLAGS or the like

AC_MSG_CHECKING(if we're building on Solaris)

case "$host" in
  *-*-solaris*)
    extralibflags="-lm -lnsl -lsocket"
	AC_MSG_RESULT(yes)

	#
	# Check for Solaris libraries
	#

	AC_CHECK_LIB(m, sqrt)
	AC_CHECK_LIB(nsl, gethostbyname)
	AC_CHECK_LIB(socket, connect)
    ;;
  *)
    AC_MSG_RESULT(no)
    extralibflags=""
    ;;
esac

#----------------------------------------------------------------------

#
# FHS compliance
#

AC_ARG_ENABLE(root-check,
    [  --disable-root-check    Disables root user check when compiling vpopmail ], idtest='false', idtest='true')

#----------------------------------------------------------------------

if $idtest && test `$idcommand` != "0"
then
  AC_MSG_WARN(=== vpopmail must be configured as root. ===)
  AC_MSG_WARN(=== please switch to the root user and   ===)
  AC_MSG_WARN(=== run ./configure.                     ===)
  AC_MSG_ERROR(aborted.)
fi

#
# Locate the qmail directory
#

AC_MSG_CHECKING(whether we can locate the qmail directory)

QMAIL_POSSIBLE_LOCATIONS="/var/qmail"

qmaildir=""
for f in $QMAIL_POSSIBLE_LOCATIONS
do
    if test -d $f
    then
        qmaildir=$f
    fi
done

AC_ARG_ENABLE(qmaildir,
    [  --enable-qmaildir=DIR      Directory where qmail control and user directories are installed [/var/qmail].],
    qmaildir="$enableval",
    [
        if test "$qmaildir" = ""
        then
            AC_MSG_RESULT(no)
            AC_MSG_ERROR([Unable to find your qmaildir directory, specify --enable-qmaildir.])
        fi
    ]
)

AC_MSG_RESULT($qmaildir)
AC_DEFINE_UNQUOTED(QMAILDIR,"$qmaildir","")

#----------------------------------------------------------------------

AC_MSG_CHECKING(whether we can locate the qmail-newu program)
qmailnewu=""
for f in "$qmaildir"/bin/qmail-newu /usr/sbin/qmail-newu
do
    if test -f $f
    then
        qmailnewu=$f
        break
    fi
done

AC_ARG_ENABLE(qmail-newu,
    [  --enable-qmail-newu=PATH   Full path to qmail-newu program.],
    qmailnewu="$enableval",
    [
        if test "$qmailnewu" = ""
        then
            AC_MSG_RESULT(no)
            AC_MSG_ERROR([Unable to find your qmail-newu file, specify --enable-qmail-newu.])
        fi
    ]
)

if test ! -f "$qmailnewu"
then
    AC_MSG_RESULT(no)
    AC_MSG_ERROR([Unable to find your qmail-newu file, specify --enable-qmail-newu=/full/path/to/qmail-newu])
fi

AC_MSG_RESULT(yes)
AC_DEFINE_UNQUOTED(QMAILNEWU,"$qmailnewu","")

#----------------------------------------------------------------------

AC_MSG_CHECKING(whether we can locate the qmail-inject program)
qmailinject=""
for f in "$qmaildir"/bin/qmail-inject /usr/sbin/qmail-inject /usr/bin/qmail-inject
do
    if test -f $f
    then
        qmailinject=$f
        break
    fi
done

AC_ARG_ENABLE(qmail-inject,
    [  --enable-qmail-inject=PATH Full path to qmail-inject program.],
    qmailinject="$enableval",
    [
        if test "$qmailinject" = ""
        then
            AC_MSG_RESULT(no)
            AC_MSG_ERROR([Unable to find your qmailinject file, specify --enable-qmail-inject.])
        fi
    ]
)

if test ! -f "$qmailinject"
then
    AC_MSG_RESULT(no)
    AC_MSG_ERROR([Unable to find your qmail-inject file, specify --enable-qmail-inject=/full/path/to/qmail-inject])
fi

AC_MSG_RESULT(yes)
AC_DEFINE_UNQUOTED(QMAILINJECT,"$qmailinject","")

#----------------------------------------------------------------------

AC_MSG_CHECKING(whether we can locate the qmail-newmrh program)
qmailnewmrh=""
for f in "$qmaildir"/bin/qmail-newmrh /usr/sbin/qmail-newmrh
do
    if test -f $f
    then
        qmailnewmrh=$f
        break
    fi
done

AC_ARG_ENABLE(qmail-newmrh,
    [  --enable-qmail-newmrh=PATH Full path to qmail-newmrh program.],
    qmailnewmrh="$enableval",
    [
        if test "$qmailnewmrh" = ""
        then
            AC_MSG_RESULT(no)
            AC_MSG_ERROR([Unable to find your qmail-newmrh file, specify --enable-qmail-newmrh.])
        fi
    ]
)

if test ! -f "$qmailnewmrh"
then
    AC_MSG_RESULT(no)
    AC_MSG_ERROR([Unable to find your qmail-newmrh file, specify --enable-qmail-qmail-newmrh=/full/path/to/qmail-newmrh])
fi

AC_MSG_RESULT(yes)
AC_DEFINE_UNQUOTED(QMAILNEWMRH,"$qmailnewmrh","")

#----------------------------------------------------------------------

AC_MSG_CHECKING(for valid vpopmail user and group)

vpopuser="vpopmail"
AC_ARG_WITH(vpopuser,
    [  --with-vpopuser=USER     User name allocated to vpopmail [vpopmail].],
    vpopuser="$enableval",
    [
        if test "$vpopuser" = ""
        then
            AC_MSG_ERROR([Unable to find your vpopmail user, specify --with-vpopuser.])
        fi
    ]
)

AC_DEFINE_UNQUOTED(VPOPUSER,"$vpopuser","")
AC_SUBST(vpopuser)

echo $vpopuser > vpopusername

vpopgroup="vchkpw"
AC_ARG_WITH(vpopgroup,
    [  --with-vpopgroup=GROUP   Group name allocated to vpopmail [vchkpw].],
    vpopgroup="$enableval",
    [
        if test "$vpopgroup" = ""
        then
            AC_MSG_ERROR([Unable to find your vpopmail group, specify --with-vpopgroup.])
        fi
    ]
)

AC_DEFINE_UNQUOTED(VPOPGROUP,"$vpopgroup","")
AC_SUBST(vpopgroup)

AC_MSG_RESULT(yes)

AC_MSG_CHECKING(whether password file entry for the vpopmail user exists)
AC_TRY_RUN( [
  #include <stdio.h>
  #include <pwd.h>
  #include <stdlib.h>

  int main() {
    struct passwd *pw;
    char tmpbuf[100];
    FILE *f;

        unlink("vpopmail.dir");
        unlink("vpopmail.uid");
        unlink("vpopmail.gid");

        if ( (f=fopen("vpopusername","r+"))==NULL) {
                printf("No vpopmail user found.\n");
                printf("Please add the vchkpw group and\n");
                printf("vpopmail user. Then run configure again\n");
                return(-1);
        }

        fgets(tmpbuf,100,f);
        fclose(f);
        tmpbuf[strlen(tmpbuf)-1] = 0;

        if (( pw=getpwnam(tmpbuf)) != 0 ) {
                f=fopen("vpopmail.dir","a+");
                fprintf(f,"%s\n", pw->pw_dir);
                fclose(f);

                f=fopen("vpopmail.uid", "a+");
                fprintf(f,"%d\n", pw->pw_uid);
                fclose(f);

                f=fopen("vpopmail.gid", "a+");
                fprintf(f,"%d\n", pw->pw_gid);
                fclose(f);
        } else {
                printf("No vpopmail user found.\n");
                printf("Please add the vchkpw group and\n");
                printf("vpopmail user. Then run configure again\n");
                return(-1);
        }
        return(0);
  }
  ],
    AC_MSG_RESULT(yes),
    AC_MSG_RESULT(no)
    AC_MSG_ERROR(Could not compile and run even a trivial ANSI C program - check CC.),
    AC_MSG_ERROR(Could not compile and run even a trivial ANSI C program - check CC.)
)

if test ! -f vpopmail.uid
then
        AC_MSG_ERROR(No vpopmail user.)
fi

if test ! -f vpopmail.gid
then
        AC_MSG_ERROR(No vpopmail group.)
fi

if test ! -f vpopmail.dir
then
        AC_MSG_ERROR(No vpopmail home directory)
fi

#
# Determine directories
#

AC_MSG_CHECKING(directory layout)

vpopmaildir=`cat vpopmail.dir`
rm -f vpopmail.dir

if test "$prefix" = "NONE"
then
   AC_MSG_RESULT(vpopmail style)
   prefix=$vpopmaildir
   AC_SUBST(prefix,$vpopmaildir)
   localstatedir=$prefix"/domains"
   AC_SUBST(localstatedir,$localstatedir)
else
   AC_MSG_RESULT(FHS)
   eval localstatedir=$localstatedir"/vpopmail"
   eval sysconfdir=$sysconfdir"/vpopmail"
   eval includedir=$includedir"/vpopmail"
fi

if test "$exec_prefix" = "NONE"
then
   eval exec_prefix=$prefix
fi

eval vpopmail_dir_bin=$bindir
eval vpopmail_dir_etc=$sysconfdir
eval vpopmail_dir_lib=$libdir
eval vpopmail_dir_domains=$localstatedir
eval vpopmail_dir_include=$includedir

AC_DEFINE_UNQUOTED(VPOPMAIL_DIR_BIN,"$vpopmail_dir_bin","")
AC_DEFINE_UNQUOTED(VPOPMAIL_DIR_ETC,"$vpopmail_dir_etc","")
AC_DEFINE_UNQUOTED(VPOPMAIL_DIR_LIB,"$vpopmail_dir_lib","")
AC_DEFINE_UNQUOTED(VPOPMAIL_DIR_INCLUDE,"$vpopmail_dir_include","")
AC_DEFINE_UNQUOTED(VPOPMAIL_DIR_DOMAINS,"$vpopmail_dir_domains","")

AC_SUBST(VPOPMAIL_DIR_BIN, $vpopmail_dir_bin)
AC_SUBST(VPOPMAIL_DIR_ETC, $vpopmail_dir_etc)
AC_SUBST(VPOPMAIL_DIR_LIB, $vpopmail_dir_lib)
AC_SUBST(VPOPMAIL_DIR_INCLUDE, $vpopmail_dir_include)
AC_SUBST(VPOPMAIL_DIR_DOMAINS, $vpopmail_dir_domains)

#
# UID:GID
#

vpopmailuid=`cat vpopmail.uid`
AC_DEFINE_UNQUOTED(VPOPMAILUID,$vpopmailuid,"")
rm -f vpopmail.uid

vpopmailgid=`cat vpopmail.gid`
AC_DEFINE_UNQUOTED(VPOPMAILGID,$vpopmailgid,"")
rm -f vpopmail.gid
rm -f vpopusername

#
# Create etc directory if root
#

if test ! -d $vpopmail_etc_dir
then
   if test ! $idtest
   then
	  AC_MSG_WARN($vpopmail_dir_etc does not exist!)
	  sleep 3
   else
	  AC_MSG_WARN(making vpopmail etc directory)
	  mkdir -p $vpopmail_dir_etc
	  chown $vpopmailuid $vpopmail_dir_etc
	  chgrp $vpopmailgid $vpopmail_dir_etc
	  chmod 755 $vpopmail_dir_etc
   fi
fi

#----------------------------------------------------------------------

AC_MSG_CHECKING(whether roaming-users has been enabled)
AC_ARG_ENABLE(roaming-users,
    [  --enable-roaming-users     Enable POP-before-SMTP functionality.],
    POPRELAY=$enableval,
        [
            POPRELAY=no
        ]
)

case $POPRELAY in
  1*|y*|Y*)
    AC_MSG_RESULT(yes)
    POPRELAY=1
    AC_DEFINE_UNQUOTED(POP_AUTH_OPEN_RELAY,$POPRELAY,"")

    AC_MSG_CHECKING(whether we can locate the tcprules program)
    for f in /usr/local/bin/tcprules /usr/bin/tcprules
    do
        if test -f $f
        then
            tcprules_prog=$f
            break
        fi
    done

    AC_ARG_ENABLE(tcprules-prog,
        [  --enable-tcprules-prog=PATH    Full path to tcprules program [/usr/{local/}bin/tcprules].],
        tcprules_prog="$enableval",
        [
            if test "$tcprules_prog" = ""
            then
                AC_MSG_RESULT(no)
                AC_MSG_ERROR([Unable to find your tcprules prog, specify --enable-tcprules-prog.])
            fi
        ]
    )

    if test ! -f "$tcprules_prog"
    then
        AC_MSG_RESULT(no)
        AC_MSG_ERROR([Unable to find your tcprulesfile, specify --enable-tcprules-prog=/full/path/to/tcprules])
    fi

    AC_MSG_RESULT(yes)
    AC_DEFINE_UNQUOTED(TCPRULES_PROG,"$tcprules_prog","")


    AC_MSG_CHECKING(whether we can locate the tcp.smtp file)
    tcpserver_file=""
    for f in "$sysconfdir"/tcp.smtp /etc/tcp.smtp /etc/tcprules.d/qmail-smtpd
    do
        if test -f $f
        then
            tcpserver_file=$f
            break
        fi
    done

    AC_ARG_ENABLE(tcpserver_file,
        [  --enable-tcpserver-file=PATH   File where tcpserver -x relay information is stored [/home/vpopmail/etc/tcp.smtp].],
        tcpserver_file="$enableval",
        [
            if test "$tcpserver_file" = ""
            then
                AC_MSG_WARN([Unable to find your tcpserver relay file.])
                AC_MSG_WARN([Creating tcp.smtp in "$sysconfdir"/tcp.smtp.])

                echo "127.:allow,RELAYCLIENT=\"\"" > "$sysconfdir"/tcp.smtp
                tcpserver_file="$sysconfdir"/tcp.smtp
            fi
        ]
    )

    if test ! -f "$tcpserver_file"
    then
        AC_MSG_ERROR([Unable to find your tcp.smtp file, specify --enable-tcpserver-path=/full/path/to/tcp.smtp])
    fi

    AC_MSG_RESULT(yes)
    AC_DEFINE_UNQUOTED(TCP_FILE,"$tcpserver_file","")


    AC_MSG_CHECKING(whether rebuild-tcpserver-file is been enabled)
    AC_ARG_ENABLE(rebuild-tcpserver-file,
        [  --disable-rebuild-tcpserver-file  Disable rebuilding of tcpserver relay control file.],
        REBUILD_TCPSERVER=$enableval,
                [
                        REBUILD_TCPSERVER=y
                ]
    )

    case $REBUILD_TCPSERVER in
      1*|y*|Y*)
        AC_MSG_RESULT(yes)
        REBUILD_TCPSERVER=1
        AC_DEFINE_UNQUOTED(REBUILD_TCPSERVER,$REBUILD_TCPSERVER,"")
        ;;
      *)
        AC_MSG_RESULT(no)
        ;;
    esac


    relay_clear_minutes="180"
    AC_ARG_ENABLE(relay-clear-minutes,
        [  --enable-relay-clear-minutes=#    Expire time for roaming users after pop authentication [180].],
        relay_clear_minutes="$enableval",
    )

    AC_DEFINE_UNQUOTED(RELAY_CLEAR_MINUTES,$relay_clear_minutes,"")


    open_smtp_cur="$sysconfdir/open-smtp"
    open_smtp_tmp="$sysconfdir/open-smtp.tmp"
    open_smtp_lok="$sysconfdir/open-smtp.lock"
    AC_DEFINE_UNQUOTED(OPEN_SMTP_CUR_FILE,"$open_smtp_cur","")
    AC_DEFINE_UNQUOTED(OPEN_SMTP_TMP_FILE,"$open_smtp_tmp","")
    AC_DEFINE_UNQUOTED(OPEN_SMTP_LOK_FILE,"$open_smtp_lok","")
    ;;
  *)
    AC_MSG_RESULT(no)
    ;;
esac

#----------------------------------------------------------------------

AC_MSG_CHECKING(whether learn-passwords is enabled)
AC_ARG_ENABLE(learn-passwords,
        [  --enable-learn-passwords   If no password is stored for a user, learn it the first time they authenticate.],
        ENABLE_LEARN_PASSWORDS=$enableval,
                [
                        ENABLE_LEARN_PASSWORDS=n
                ]
)

case $ENABLE_LEARN_PASSWORDS in
  1*|y*|Y*)
      AC_MSG_RESULT(yes)
      ENABLE_LEARN_PASSWORDS=1
      AC_DEFINE_UNQUOTED(ENABLE_LEARN_PASSWORDS,$ENABLE_LEARN_PASSWORDS,"")
      ;;
  *)
      AC_MSG_RESULT(no)
      ;;
esac

#----------------------------------------------------------------------

AC_MSG_CHECKING(whether md5-passwords is enabled)
AC_ARG_ENABLE(md5-passwords,
        [  --disable-md5-passwords    Use DES crypt() instead of MD5 encryption for passwords.],
        ENABLE_MD5_PASSWORDS=$enableval,
                [
                        ENABLE_MD5_PASSWORDS=y
                ]
)

case $ENABLE_MD5_PASSWORDS in
  1*|y*|Y*)
      AC_MSG_RESULT(yes)
      ENABLE_MD5_PASSWORDS=1
      AC_DEFINE_UNQUOTED(MD5_PASSWORDS,$ENABLE_MD5_PASSWORDS,"")

	  AC_MSG_CHECKING(whether system supports MD5 passwords)
	  AC_TRY_RUN([
		 #include <stdio.h>
	     #include <string.h>
	     #include <unistd.h>

	     int main(int argc, char *argv[])
	     {
	  	  char *ret = NULL;
	  	  const char salt[12] = "\$1\$ABCDEFG\0", key[5] = "test\0";

	  	  ret = (char *)crypt(key, salt);

	  	  if (ret == NULL)
		 	 return 2;

	  	  if (*(ret + 2) != '$')
	  		 return 1;

	  	  return 0;
	     }
		 ], 
			[
			   AC_MSG_RESULT(yes)],
			[
			   AC_MSG_RESULT(no)
			   AC_MSG_ERROR(Your system does not support MD5 passwords.  You must use the --disable-md5-passwords option)
			]
)

      ;;
  *)
      AC_MSG_RESULT(no)
      ;;
esac

#----------------------------------------------------------------------

AC_MSG_CHECKING(whether file-locking is enabled)
AC_ARG_ENABLE(file-locking,
        [  --disable-file-locking     Don't use file locking.],
        FILE_LOCKING=$enableval,
                [
                        FILE_LOCKING=y
                ]
)

case $FILE_LOCKING in
  1*|y*|Y*)
      AC_MSG_RESULT(yes)
      FILE_LOCKING=1
      AC_DEFINE_UNQUOTED(FILE_LOCKING,$FILE_LOCKING,"")
      ;;
  *)
      AC_MSG_RESULT(no)
      ;;
esac

#----------------------------------------------------------------------

AC_MSG_CHECKING(whether file-sync is enabled)
AC_ARG_ENABLE(file-sync,
        [  --enable-file-sync         Enable file sync after each message is delivered.],
        FILE_SYNC=$enableval,
                [
                        FILE_SYNC=n
                ]
)

case $FILE_SYNC in
  1*|y*|Y*)
      AC_MSG_RESULT(yes)
      FILE_SYNC=1
      AC_DEFINE_UNQUOTED(FILE_SYNC,$FILE_SYNC,"")
      ;;
  *)
      AC_MSG_RESULT(no)
      ;;
esac

#----------------------------------------------------------------------

AC_MSG_CHECKING(whether make-seekable is enabled)
AC_ARG_ENABLE(make-seekable,
        [  --disable-make-seekable    Don't try to make input to vdelivermail seekable.],
        MAKE_SEEKABLE=$enableval,
                [
                        MAKE_SEEKABLE=y
                ]
)

case $MAKE_SEEKABLE in
  1*|y*|Y*)
      AC_MSG_RESULT(yes)
      MAKE_SEEKABLE=1
      AC_DEFINE_UNQUOTED(MAKE_SEEKABLE,$MAKE_SEEKABLE,"")
      ;;
  *)
      AC_MSG_RESULT(no)
      ;;
esac

#----------------------------------------------------------------------

AC_MSG_CHECKING(whether clear-passwd is enabled)
AC_ARG_ENABLE(clear-passwd,
        [  --disable-clear-passwd     Don't store a cleartext version of the password in addition to the encrypted version.],
        CLEAR_PASS=$enableval,
                [
                        CLEAR_PASS=y
                ]
)

case $CLEAR_PASS in
  1*|y*|Y*)
      AC_MSG_RESULT(yes)
      CLEAR_PASS=1
      AC_DEFINE_UNQUOTED(CLEAR_PASS,$CLEAR_PASS,"")
      ;;
  *)
      AC_MSG_RESULT(no)
      ;;
esac

#----------------------------------------------------------------------

AC_MSG_CHECKING(whether user-big-dir is enabled)
AC_ARG_ENABLE(users-big-dir,
        [  --disable-users-big-dir    Disable hashing of user directories.],
        USERS_BIG_DIR=$enableval,
                [
                        USERS_BIG_DIR=y
                ]
)

case $USERS_BIG_DIR in
  1*|y*|Y*)
      AC_MSG_RESULT(yes)
      USERS_BIG_DIR=1
      AC_DEFINE_UNQUOTED(USERS_BIG_DIR,$USERS_BIG_DIR,"")
      ;;
  *)
      AC_MSG_RESULT(no)
      ;;
esac

#----------------------------------------------------------------------

AC_MSG_CHECKING(whether sqwebmail-pass is enabled)
AC_ARG_ENABLE(sqwebmail-pass,
        [  --enable-sqwebmail-pass    Store a copy of the user's password in the the user's maildir for use by pre-v3 sqwebmail.],
        ENABLE_SQWEBMAIL_PASS=$enableval,
                [
                        ENABLE_SQWEBMAIL_PASS=n
                ]
)

case $ENABLE_SQWEBMAIL_PASS in
  1*|y*|Y*)
          AC_MSG_RESULT(yes)
          ENABLE_SQWEBMAIL_PASS=1
          AC_DEFINE_UNQUOTED(SQWEBMAIL_PASS,$ENABLE_SQWEBMAIL_PASS,"")
          ;;
  *)
          AC_MSG_RESULT(no)
          ;;
esac

#----------------------------------------------------------------------

AC_MSG_CHECKING(whether qmail-ext is enabled)
AC_ARG_ENABLE(qmail-ext,
        [  --enable-qmail-ext         Enable qmail email address extension support.],
        QMAIL_EXT=$enableval,
                [
                        QMAIL_EXT=n
                ]
)

case $QMAIL_EXT in
  1*|y*|Y*)
        AC_MSG_RESULT(yes)
        QMAIL_EXT=1
        AC_DEFINE_UNQUOTED(QMAIL_EXT,$QMAIL_EXT,"")
        ;;
  *)
        AC_MSG_RESULT(no)
        ;;
esac

#----------------------------------------------------------------------

AC_MSG_CHECKING(whether ip-alias-domains is enabled)
AC_ARG_ENABLE(ip-alias-domains,
        [  --enable-ip-alias-domains  Enable mapping of default domain via reverse ip lookup table.],
        IPALIAS=$enableval,
                [
                        IPALIAS=no
                ]
)

case $IPALIAS in
  1*|y*|Y*)
        AC_MSG_RESULT(yes)
        IPALIAS=1
        AC_DEFINE_UNQUOTED(IP_ALIAS_DOMAINS,$IPALIAS,"")
        ;;
  *)
        AC_MSG_RESULT(no)
        ;;
esac

#----------------------------------------------------------------------

AC_MSG_CHECKING(whether onchange script is enabled)
AC_ARG_ENABLE(onchange-script,
        [  --enable-onchange-script   Enable onchange script. See README.onchange for more info.],
        ENABLE_ONCHANGE_SCRIPT=$enableval,
                [
                        ENABLE_ONCHANGE_SCRIPT=0
                ]
)

case $ENABLE_ONCHANGE_SCRIPT in
  1*|y*|Y*)
      AC_MSG_RESULT(yes)
      ENABLE_ONCHANGE_SCRIPT=1
      AC_DEFINE_UNQUOTED(ONCHANGE_SCRIPT,$ENABLE_ONCHANGE_SCRIPT,"")
      ;;
  *)
      AC_MSG_RESULT(no)
      ;;
esac

#----------------------------------------------------------------------


#----------------------------------------------------------------------

AC_MSG_CHECKING(whether spamassassin is enabled)
AC_ARG_ENABLE(spamassassin,
        [  --enable-spamassassin      Enable spamassassin. See  README.spamassassin for more info.],
        ENABLE_SPAMASSASSIN=$enableval,
                [
                        ENABLE_SPAMASSASSIN=0
                ]
)

case $ENABLE_SPAMASSASSIN in
  0*|n*|N*)
      AC_MSG_RESULT(no)
      ;;
  *)
      AC_MSG_RESULT(yes)
      ENABLE_SPAMASSASSIN=1
      AC_DEFINE_UNQUOTED(SPAMASSASSIN,$ENABLE_SPAMASSASSIN,"")

    AC_MSG_CHECKING(whether we can locate the spamc program)
    for f in /usr/bin/spamc /usr/local/bin/spamc
    do
        if test -f $f
        then
            spamc_prog=$f
            break
        fi
    done
    AC_ARG_ENABLE(spamc-prog,
        [  --enable-spamc-prog=PATH   Full path to spamc program [/usr/{local/}bin/spamc].],
        spamc_prog="$enableval",
        [
            if test "$spamc_prog" = ""
            then
                AC_MSG_RESULT(no)
                AC_MSG_ERROR([Unable to find your spamc prog, specify --enable-spamc-prog.])
            fi
        ]
    )

    if test ! -f "$spamc_prog"
    then
        AC_MSG_RESULT(no)
        AC_MSG_ERROR([Unable to find your spamc program, specify --enable-spamc-prog=/full/path/to/spamc])
    fi

    AC_MSG_RESULT(yes)
    AC_DEFINE_UNQUOTED(SPAMC_PROG,"$spamc_prog","")

      ;;
esac

#----------------------------------------------------------------------

AC_MSG_CHECKING(whether maildrop is enabled)
AC_ARG_ENABLE(maildrop,
        [  --enable-maildrop          Enable maildrop. See  README.maildrop for more info.],
        ENABLE_MAILDROP=$enableval,
                [
                        ENABLE_MAILDROP=0
                ]
)

case $ENABLE_MAILDROP in
  0*|n*|N*)
      AC_MSG_RESULT(no)
      ;;
  *)
      AC_MSG_RESULT(yes)
      ENABLE_MAILDROP=1
      AC_DEFINE_UNQUOTED(MAILDROP,$ENABLE_MAILDROP,"")

    AC_MSG_CHECKING(whether we can locate the maildrop program)
    for f in /usr/bin/maildrop /usr/local/bin/maildrop
    do
        if test -f $f
        then
            maildrop_prog=$f
            break
        fi
    done
    AC_ARG_ENABLE(maildrop-prog,
        [  --enable-maildrop-prog=PATH    Full path to maildrop program [/usr/{local/}bin/maildrop].],
        maildrop_prog="$enableval",
        [
            if test "$maildrop_prog" = ""
            then
                AC_MSG_RESULT(no)
                AC_MSG_ERROR([Unable to find your maildrop prog, specify --enable-maildrop-prog.])
            fi
        ]
    )

    if test ! -f "$maildrop_prog"
    then
        AC_MSG_RESULT(no)
        AC_MSG_ERROR([Unable to find your maildrop program, specify --enable-maildrop-prog=/full/path/to/maildrop])
    fi

    AC_MSG_RESULT(yes)
    AC_DEFINE_UNQUOTED(MAILDROP_PROG,"$maildrop_prog","")

      ;;
esac

#----------------------------------------------------------------------
AC_MSG_CHECKING(whether domainquotas is enabled)
AC_ARG_ENABLE(domainquotas,
        [  --disable-domainquotas      Disable non-system domain quotas. See README.quotas for more info.],
        ENABLE_DOMAIN_QUOTAS=$enableval,
                [
                        ENABLE_DOMAIN_QUOTAS=1
                ]
)

case $ENABLE_DOMAIN_QUOTAS in
  0*|n*|N*)
      AC_MSG_RESULT(no)
      ;;
  *)
      AC_MSG_RESULT(yes)
      ENABLE_DOMAIN_QUOTAS=1
      AC_DEFINE_UNQUOTED(DOMAIN_QUOTAS,$ENABLE_DOMAIN_QUOTAS,"")
      ;;
esac

#----------------------------------------------------------------------

eval vlimits_default="$sysconfdir/vlimits.default"

AC_DEFINE_UNQUOTED(VLIMITS_DEFAULT_FILE,"$vlimits_default","")

#----------------------------------------------------------------------

#domains_dir="domains"

#AC_ARG_ENABLE(domains-dir,
#    [  --enable-domains-dir=TEXT  Directory in ~vpopmail to store domains (default=domains).],
#    domains_dir="$enableval",
#)

#AC_DEFINE_UNQUOTED(DOMAINS_DIR,"$domains_dir","")
#AC_SUBST(domains_dir)

#----------------------------------------------------------------------

AC_MSG_CHECKING(whether system accounts have been enabled)
AC_ARG_ENABLE(passwd,
        [  --enable-passwd            Enable /etc/passwd (or shadow) accounts in addition to virtual domains.],
        ENABLE_PASSWD=$enableval,
                [
                        ENABLE_PASSWD=no
                ]
)

case $ENABLE_PASSWD in
  1*|y*|Y*)
        AC_MSG_RESULT(yes)
        ENABLE_PASSWD=1

        AC_CHECK_HEADERS(shadow.h)
        HAS_SHADOW_H=0
        AC_CHECK_HEADER(shadow.h,
                [
                        HAS_SHADOW_H=1;
                ] )
        # if test $HAS_SHADOW_H = 1
        # then
        #        AC_CHECK_LIB(shadow, setspent)
        # fi
                AC_DEFINE_UNQUOTED(ENABLE_PASSWD,$ENABLE_PASSWD,"")
        ;;
  *)
        AC_MSG_RESULT(no)
        ENABLE_PASSWD=0
        ;;
esac

#----------------------------------------------------------------------

AC_MSG_CHECKING(whether /etc/shadow exists)
if test -f /etc/shadow
then
        AC_MSG_RESULT(yes)
        HAS_SHADOW=1
        AC_DEFINE_UNQUOTED(HAS_SHADOW,$HAS_SHADOW,"")
else
        AC_MSG_RESULT(no)
fi

#----------------------------------------------------------------------

AC_MSG_CHECKING(whether logging is enabled)
AC_ARG_ENABLE(logging,
        [  --enable-logging=OPT       Log to syslog: n=nothing, e=errors only (default), y=all attempts, p=errors with passwords, v=verbose (all attempts, with passwords).],
        ENABLE_LOGGING=$enableval,
                [
                        ENABLE_LOGGING=e
                ]
)

case $ENABLE_LOGGING in
  1*|y*|Y*)
      AC_MSG_RESULT(all attempts)
      ENABLE_LOGGING=1
          AC_DEFINE_UNQUOTED(ENABLE_LOGGING,$ENABLE_LOGGING,"")
      ;;
  e*|E*)
      AC_MSG_RESULT(errors only)
      ENABLE_LOGGING=2
          AC_DEFINE_UNQUOTED(ENABLE_LOGGING,$ENABLE_LOGGING,"")
          ;;
  p*|P*)
      AC_MSG_RESULT([errors, with password])
      ENABLE_LOGGING=3
          AC_DEFINE_UNQUOTED(ENABLE_LOGGING,$ENABLE_LOGGING,"")
          ;;
  v*|V*)
      AC_MSG_RESULT([verbose, all with password])
       ENABLE_LOGGING=4
          AC_DEFINE_UNQUOTED(ENABLE_LOGGING,$ENABLE_LOGGING,"")
          ;;
  *)
      AC_MSG_RESULT(no)
      ENABLE_LOGGING=0
          AC_DEFINE_UNQUOTED(ENABLE_LOGGING,$ENABLE_LOGGING,"")
          ;;
esac

#----------------------------------------------------------------------

log_name="vpopmail"
AC_ARG_ENABLE(log-name,
    [  --enable-log-name=TEXT     Set syslog name [vpopmail].],
    log_name="$enableval",
)

AC_DEFINE_UNQUOTED(LOG_NAME,"$log_name","")

#
# Check if we can compile vusaged
#

#
# Check for pthreads support
#

# ===========================================================================
#              http://autoconf-archive.cryp.to/acx_pthread.html
# ===========================================================================
#
# SYNOPSIS
#
#   ACX_PTHREAD([ACTION-IF-FOUND[, ACTION-IF-NOT-FOUND]])
#
# DESCRIPTION
#
#   This macro figures out how to build C programs using POSIX threads. It
#   sets the PTHREAD_LIBS output variable to the threads library and linker
#   flags, and the PTHREAD_CFLAGS output variable to any special C compiler
#   flags that are needed. (The user can also force certain compiler
#   flags/libs to be tested by setting these environment variables.)
#
#   Also sets PTHREAD_CC to any special C compiler that is needed for
#   multi-threaded programs (defaults to the value of CC otherwise). (This
#   is necessary on AIX to use the special cc_r compiler alias.)
#
#   NOTE: You are assumed to not only compile your program with these flags,
#   but also link it with them as well. e.g. you should link with
#   $PTHREAD_CC $CFLAGS $PTHREAD_CFLAGS $LDFLAGS ... $PTHREAD_LIBS $LIBS
#
#   If you are only building threads programs, you may wish to use these
#   variables in your default LIBS, CFLAGS, and CC:
#
#          LIBS="$PTHREAD_LIBS $LIBS"
#          CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
#          CC="$PTHREAD_CC"
#
#   In addition, if the PTHREAD_CREATE_JOINABLE thread-attribute constant
#   has a nonstandard name, defines PTHREAD_CREATE_JOINABLE to that name
#   (e.g. PTHREAD_CREATE_UNDETACHED on AIX).
#
#   ACTION-IF-FOUND is a list of shell commands to run if a threads library
#   is found, and ACTION-IF-NOT-FOUND is a list of commands to run it if it
#   is not found. If ACTION-IF-FOUND is not specified, the default action
#   will define HAVE_PTHREAD.
#
#   Please let the authors know if this macro fails on any platform, or if
#   you have any other suggestions or comments. This macro was based on work
#   by SGJ on autoconf scripts for FFTW (http://www.fftw.org/) (with help
#   from M. Frigo), as well as ac_pthread and hb_pthread macros posted by
#   Alejandro Forero Cuervo to the autoconf macro repository. We are also
#   grateful for the helpful feedback of numerous users.
#
# LAST MODIFICATION
#
#   2008-04-12
#
# COPYLEFT
#
#   Copyright (c) 2008 Steven G. Johnson <stevenj@alum.mit.edu>
#
#   This program is free software: you can redistribute it and/or modify it
#   under the terms of the GNU General Public License as published by the
#   Free Software Foundation, either version 3 of the License, or (at your
#   option) any later version.
#
#   This program is distributed in the hope that it will be useful, but
#   WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
#   Public License for more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program. If not, see <http://www.gnu.org/licenses/>.
#
#   As a special exception, the respective Autoconf Macro's copyright owner
#   gives unlimited permission to copy, distribute and modify the configure
#   scripts that are the output of Autoconf when processing the Macro. You
#   need not follow the terms of the GNU General Public License when using
#   or distributing such scripts, even though portions of the text of the
#   Macro appear in them. The GNU General Public License (GPL) does govern
#   all other use of the material that constitutes the Autoconf Macro.
#
#   This special exception to the GPL applies to versions of the Autoconf
#   Macro released by the Autoconf Macro Archive. When you make and
#   distribute a modified version of the Autoconf Macro, you may extend this
#   special exception to the GPL to apply to your modified version as well.

AC_DEFUN([ACX_PTHREAD], [
AC_REQUIRE([AC_CANONICAL_HOST])
AC_LANG_SAVE
AC_LANG_C
acx_pthread_ok=no

# We used to check for pthread.h first, but this fails if pthread.h
# requires special compiler flags (e.g. on True64 or Sequent).
# It gets checked for in the link test anyway.

# First of all, check if the user has set any of the PTHREAD_LIBS,
# etcetera environment variables, and if threads linking works using
# them:
if test x"$PTHREAD_LIBS$PTHREAD_CFLAGS" != x; then
        save_CFLAGS="$CFLAGS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
        save_LIBS="$LIBS"
        LIBS="$PTHREAD_LIBS $LIBS"
        AC_MSG_CHECKING([for pthread_join in LIBS=$PTHREAD_LIBS with CFLAGS=$PTHREAD_CFLAGS])
        AC_TRY_LINK_FUNC(pthread_join, acx_pthread_ok=yes)
        AC_MSG_RESULT($acx_pthread_ok)
        if test x"$acx_pthread_ok" = xno; then
                PTHREAD_LIBS=""
                PTHREAD_CFLAGS=""
        fi
        LIBS="$save_LIBS"
        CFLAGS="$save_CFLAGS"
fi

# We must check for the threads library under a number of different
# names; the ordering is very important because some systems
# (e.g. DEC) have both -lpthread and -lpthreads, where one of the
# libraries is broken (non-POSIX).

# Create a list of thread flags to try.  Items starting with a "-" are
# C compiler flags, and other items are library names, except for "none"
# which indicates that we try without any flags at all, and "pthread-config"
# which is a program returning the flags for the Pth emulation library.

acx_pthread_flags="pthreads none -Kthread -kthread lthread -pthread -pthreads -mthreads pthread --thread-safe -mt pthread-config"

# The ordering *is* (sometimes) important.  Some notes on the
# individual items follow:

# pthreads: AIX (must check this before -lpthread)
# none: in case threads are in libc; should be tried before -Kthread and
#       other compiler flags to prevent continual compiler warnings
# -Kthread: Sequent (threads in libc, but -Kthread needed for pthread.h)
# -kthread: FreeBSD kernel threads (preferred to -pthread since SMP-able)
# lthread: LinuxThreads port on FreeBSD (also preferred to -pthread)
# -pthread: Linux/gcc (kernel threads), BSD/gcc (userland threads)
# -pthreads: Solaris/gcc
# -mthreads: Mingw32/gcc, Lynx/gcc
# -mt: Sun Workshop C (may only link SunOS threads [-lthread], but it
#      doesn't hurt to check since this sometimes defines pthreads too;
#      also defines -D_REENTRANT)
#      ... -mt is also the pthreads flag for HP/aCC
# pthread: Linux, etcetera
# --thread-safe: KAI C++
# pthread-config: use pthread-config program (for GNU Pth library)

case "${host_cpu}-${host_os}" in
        *solaris*)

        # On Solaris (at least, for some versions), libc contains stubbed
        # (non-functional) versions of the pthreads routines, so link-based
        # tests will erroneously succeed.  (We need to link with -pthreads/-mt/
        # -lpthread.)  (The stubs are missing pthread_cleanup_push, or rather
        # a function called by this macro, so we could check for that, but
        # who knows whether they'll stub that too in a future libc.)  So,
        # we'll just look for -pthreads and -lpthread first:

        acx_pthread_flags="-pthreads pthread -mt -pthread $acx_pthread_flags"
        ;;
esac

if test x"$acx_pthread_ok" = xno; then
for flag in $acx_pthread_flags; do

        case $flag in
                none)
                AC_MSG_CHECKING([whether pthreads work without any flags])
                ;;

                -*)
                AC_MSG_CHECKING([whether pthreads work with $flag])
                PTHREAD_CFLAGS="$flag"
                ;;

		pthread-config)
		AC_CHECK_PROG(acx_pthread_config, pthread-config, yes, no)
		if test x"$acx_pthread_config" = xno; then continue; fi
		PTHREAD_CFLAGS="`pthread-config --cflags`"
		PTHREAD_LIBS="`pthread-config --ldflags` `pthread-config --libs`"
		;;

                *)
                AC_MSG_CHECKING([for the pthreads library -l$flag])
                PTHREAD_LIBS="-l$flag"
                ;;
        esac

        save_LIBS="$LIBS"
        save_CFLAGS="$CFLAGS"
        LIBS="$PTHREAD_LIBS $LIBS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"

        # Check for various functions.  We must include pthread.h,
        # since some functions may be macros.  (On the Sequent, we
        # need a special flag -Kthread to make this header compile.)
        # We check for pthread_join because it is in -lpthread on IRIX
        # while pthread_create is in libc.  We check for pthread_attr_init
        # due to DEC craziness with -lpthreads.  We check for
        # pthread_cleanup_push because it is one of the few pthread
        # functions on Solaris that doesn't have a non-functional libc stub.
        # We try pthread_create on general principles.
        AC_TRY_LINK([#include <pthread.h>],
                    [pthread_t th; pthread_join(th, 0);
                     pthread_attr_init(0); pthread_cleanup_push(0, 0);
                     pthread_create(0,0,0,0); pthread_cleanup_pop(0); ],
                    [acx_pthread_ok=yes])

        LIBS="$save_LIBS"
        CFLAGS="$save_CFLAGS"

        AC_MSG_RESULT($acx_pthread_ok)
        if test "x$acx_pthread_ok" = xyes; then
                break;
        fi

        PTHREAD_LIBS=""
        PTHREAD_CFLAGS=""
done
fi

# Various other checks:
if test "x$acx_pthread_ok" = xyes; then
        save_LIBS="$LIBS"
        LIBS="$PTHREAD_LIBS $LIBS"
        save_CFLAGS="$CFLAGS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"

        # Detect AIX lossage: JOINABLE attribute is called UNDETACHED.
	AC_MSG_CHECKING([for joinable pthread attribute])
	attr_name=unknown
	for attr in PTHREAD_CREATE_JOINABLE PTHREAD_CREATE_UNDETACHED; do
	    AC_TRY_LINK([#include <pthread.h>], [int attr=$attr; return attr;],
                        [attr_name=$attr; break])
	done
        AC_MSG_RESULT($attr_name)
        if test "$attr_name" != PTHREAD_CREATE_JOINABLE; then
            AC_DEFINE_UNQUOTED(PTHREAD_CREATE_JOINABLE, $attr_name,
                               [Define to necessary symbol if this constant
                                uses a non-standard name on your system.])
        fi

        AC_MSG_CHECKING([if more special flags are required for pthreads])
        flag=no
        case "${host_cpu}-${host_os}" in
            *-aix* | *-freebsd* | *-darwin*) flag="-D_THREAD_SAFE";;
            *solaris* | *-osf* | *-hpux*) flag="-D_REENTRANT";;
        esac
        AC_MSG_RESULT(${flag})
        if test "x$flag" != xno; then
            PTHREAD_CFLAGS="$flag $PTHREAD_CFLAGS"
        fi

        LIBS="$save_LIBS"
        CFLAGS="$save_CFLAGS"

        # More AIX lossage: must compile with xlc_r or cc_r
	if test x"$GCC" != xyes; then
          AC_CHECK_PROGS(PTHREAD_CC, xlc_r cc_r, ${CC})
        else
          PTHREAD_CC=$CC
	fi
else
        PTHREAD_CC="$CC"
fi

AC_SUBST(PTHREAD_LIBS)
AC_SUBST(PTHREAD_CFLAGS)
AC_SUBST(PTHREAD_CC)

# Finally, execute ACTION-IF-FOUND/ACTION-IF-NOT-FOUND:
if test x"$acx_pthread_ok" = xyes; then
        ifelse([$1],,AC_DEFINE(HAVE_PTHREAD,1,[Define if you have POSIX threads libraries and header files.]),[$1])
        :
else
        acx_pthread_ok=no
        $2
fi
AC_LANG_RESTORE
])dnl ACX_PTHREAD

ACX_PTHREAD()

#
# Set Makefile able to build vusaged
#

AC_SUBST(vusagedbuild, "vusaged/vusaged")

if test x"$acx_pthread_ok" == xno
then
   AC_MSG_WARN([===                                                       ===])
   AC_MSG_WARN([===               pthreads not found                      ===])
   AC_MSG_WARN([=== You will be unable to build the vpopmail usage daemon ===])
   AC_MSG_WARN([===                                                       ===])
   AC_SUBST(vusagedbuild, "")
fi

#
# Check for libev requirements
#

AC_CHECK_HEADERS(ev.h)
AC_CHECK_LIB(ev, ev_loop_new,
   [
	  AC_SUBST(VUSAGEDLIBS, "-lev")
   ], 

   [
	  AC_MSG_WARN([===                                                       ===])
	  AC_MSG_WARN([===               libev not found                         ===])
	  AC_MSG_WARN([=== You will be unable to build the vpopmail usage daemon ===])
	  AC_MSG_WARN([===                                                       ===])
	  AC_SUBST(vusagedbuild, "")
   ]
)

#----------------------------------------------------------------------

AC_MSG_CHECKING(whether any discontinued --enable commands have been used)

AC_ARG_ENABLE(valias, [],
   [
	  AC_MSG_RESULT(yes)
	  AC_MSG_ERROR(--enable-valias is no longer a vpopmail configure option.  Please use this option when compiling a backend module.)
   ]
)

AC_ARG_ENABLE(mysql-logging, [],
    [
        AC_MSG_RESULT(yes)
        AC_MSG_ERROR(--enable-mysql-logging has been superceded.  Please use --enable-sql-logging instead)
    ]
)

AC_ARG_ENABLE(pgsql-logging, [],
    [
        AC_MSG_RESULT(yes)
        AC_MSG_ERROR(--enable-pgsql-logging has been superceded.  Please use --enable-sql-logging instead)
    ]
)

AC_ARG_ENABLE(auth-module, [],
   [
	  AC_MSG_RESULT(yes)
	  AC_MSG_ERROR(--enable-auth-module is no longer used.  Please select a backend from the backends directory)
   ]
)

AC_ARG_ENABLE(mysql, [],
    [
        AC_MSG_RESULT(yes)
        AC_MSG_ERROR(--enable-mysql has been superceded. Please use --enable-auth-module=mysql instead)
    ]
)

AC_ARG_ENABLE(pgsql, [],
    [
        AC_MSG_RESULT(yes)
        AC_MSG_ERROR(--enable-pgsql has been superceded. Please use --enable-auth-module=pgsql instead)
    ]
)

AC_ARG_ENABLE(ldap, [],
    [
        AC_MSG_RESULT(yes)
        AC_MSG_ERROR(--enable-ldap has been superceded. Please use --enable-auth-module=ldap instead)
    ]
)

AC_ARG_ENABLE(oracle, [],
    [
        AC_MSG_RESULT(yes)
        AC_MSG_ERROR(--enable-oracle has been superceded. Please use --enable-auth-module=oracle instead)
    ]
)

AC_ARG_ENABLE(sybase, [],
    [
        AC_MSG_RESULT(yes)
	AC_MSG_ERROR(--enable-sybase has been superceded. Please use --enable-auth-module=sybase instead)
    ]
)

AC_ARG_ENABLE(hardquota, [],
    [
        AC_MSG_RESULT(yes)
        AC_MSG_ERROR(--enable-hardquota has been superceded. Please use the ~vpopmail/etc/vlimits.default file instead.)
    ]
)

AC_ARG_ENABLE(defaultquota, [],
    [
        AC_MSG_RESULT(yes)
        AC_MSG_ERROR(--enable-defaultquota has been superceded. Please use the ~vpopmail/etc/vlimits.default file instead.)
    ]
)

AC_ARG_ENABLE(default-domain, [],
    [
        AC_MSG_RESULT(yes)
        AC_MSG_ERROR(--enable-default-domain has been superceded. The default domain should be put into the file ~vpopmail/etc/defaultdomain instead)
    ]
)

AC_ARG_ENABLE(non-root-build, [],
    [ 
	  AC_MSG_RESULT(yes)
	  AC_MSG_ERROR(--enable-non-root-build is deprecated.  Please use --disable-root-check)
    ]
)

AC_ARG_WITH(vpopuser, [],
			[
			   AC_MSG_RESULT(yes)
			   AC_MSG_ERROR(--enable-vpopuser is deprecated.  Please use --with-vpopmail)
			]
)

AC_ARG_WITH(vpopgroup, [],
			[
			   AC_MSG_RESULT(yes)
			   AC_MSG_ERROR(--enable-vpopgroup is deprecated.  Please use --with-vpopgroup)
			]
)

AC_ARG_ENABLE(auth-logging, [],
			  [
				  AC_MSG_RESULT(yes)
				  AC_MSG_ERROR(--enable-auth-logging is a module option.  Please use --enable-auth-logging when compiling a backend module)
			   ]
)

AC_MSG_RESULT(no)

#----------------------------------------------------------------------

AC_OUTPUT(Makefile vusaged/Makefile vusaged/contrib/rc.vusaged backends/module.mk)

#----------------------------------------------------------------------


echo ""
echo "           $PACKAGE_NAME $PACKAGE_VERSION"
echo "            Current settings"
echo "---------------------------------------"
echo ""
echo " domains directory = "$vpopmail_dir_domains""
echo "    conf directory = $vpopmail_dir_etc"
echo "     bin directory = $vpopmail_dir_bin"
echo "     lib directory = $vpopmail_dir_lib"
echo " include directory = $vpopmail_dir_include"
echo "               uid = "$vpopmailuid""
echo "               gid = "$vpopmailgid""

case $POPRELAY in
  1*|y*|Y*)
    echo "     roaming users = ON  --enable-roaming-users"

    echo "    tcpserver file = $tcpserver_file"
    echo "    open_smtp file = $open_smtp_cur"

    case $REBUILD_TCPSERVER in
      1*|y*|Y*)
        echo "rebuild tcpserver file = ON  --enable-rebuild-tcpserver-file (default)"
        ;;
      *)
        echo "rebuild tcpserver file = OFF --disable-rebuild-tcpserver-file"
        ;;
    esac

    ;;
  *)
    echo "     roaming users = OFF --disable-roaming-users (default)"
    ;;
esac


case $ENABLE_LEARN_PASSWORDS in
  1*|y*|Y*)
    echo " password learning = ON  --enable-learn-passwords"
    ;;
  *)
    echo " password learning = OFF --disable-learn-passwords (default)"
    ;;
esac


case $ENABLE_MD5_PASSWORDS in
  1*|y*|Y*)
    echo "     md5 passwords = ON  --enable-md5-passwords (default)"
    ;;
  *)
    echo "     md5 passwords = OFF --disable-md5-passwords"
    ;;
esac


case $FILE_LOCKING in
  1*|y*|Y*)
    echo "      file locking = ON  --enable-file-locking (default)"
    ;;
  *)
    echo "      file locking = OFF --disable-file-locking"
    ;;
esac


case $FILE_SYNC in
  1*|y*|Y*)
    echo "vdelivermail fsync = ON  --enable-file-sync"
    ;;
  *)
    echo "vdelivermail fsync = OFF --disable-file-sync (default)"
    ;;
esac


case $MAKE_SEEKABLE in
  1*|y*|Y*)
    echo "     make seekable = ON  --enable-make-seekable (default)"
    ;;
  *)
    echo "     make seekable = OFF --disable-make-seekable"
    ;;
esac


case $CLEAR_PASS in
  1*|y*|Y*)
    echo "      clear passwd = ON  --enable-clear-passwd (default)"
    ;;
  *)
    echo "      clear passwd = OFF --disable-clear-passwd"
    ;;
esac


case $USERS_BIG_DIR in
  1*|y*|Y*)
    echo " user dir hashing  = ON  --enable-users-big-dir (default)"
    ;;
  *)
    echo " user dir hashing  = OFF --disable-users-big-dir"
    ;;
esac


# SQWEBMAIL PASS


case $QMAIL_EXT in
  1*|y*|Y*)
    echo "address extensions = ON  --enable-qmail-ext"
    ;;
  *)
    echo "address extensions = OFF --disable-qmail-ext (default)"
    ;;
esac


case $IPALIAS in
  1*|y*|Y*)
    echo "          ip alias = ON  --enable-ip-alias-domains"
    ;;
  *)
    echo "          ip alias = OFF --disable-ip-alias-domains (default)"
    ;;
esac


case $ENABLE_ONCHANGE_SCRIPT in
  1*|y*|Y*)
    echo "   onchange script = ON  --enable-onchange-script"
    ;;
  *)
    echo "   onchange script = OFF --disable-onchange-script (default)"
    ;;
esac


case $ENABLE_DOMAIN_QUOTAS in
  1*|y*|Y*)
    echo "     domain quotas = ON  --enable-domainquotas (default)"
    ;;
  *)
    echo "     domain quotas = OFF --disable-domainquotas"
    ;;
esac


case $ENABLE_PASSWD in
  1*|y*|Y*)
    echo "  system passwords = ON  --enable-passwd"
    ;;
  *)
    echo "  system passwords = OFF --disable-passwd (default)"
    ;;
esac


case $ENABLE_LOGGING in
  1*|y*|Y*)
    echo "        pop syslog = show successful and failed login attempts --enable-logging=y"
    ;;
  2*|e*|E*)
    echo "        pop syslog = show only failed attempts --enable-logging=e (default)"
    ;;
  3*|p*|P*)
    echo "        pop syslog = show failed attempts with clear text password --enable-logging=p"
    ;;
  4*|v*|V*)
    echo "        pop syslog = log success and errors including passwords --enable-logging=v"
    ;;
  *)
    echo "        pop syslog = OFF"
    ;;
esac

if test "$USE_SQL" = 1
then
  if test "$MANY_DOMAINS" = 1
  then
    echo "all domains in one SQL table = --enable-many-domains (default)"
  else
    echo "one domain per SQL table     = --disable-many-domains"
  fi
fi

case $ENABLE_SPAMASSASSIN in
  1*|y*|Y*)
    echo "      spamassassin = ON  --enable-spamassassin"
    ;;
  *)
    echo "      spamassassin = OFF --disable-spamassassin (default)"
    ;;
esac

case $ENABLE_MAILDROP in
  1*|y*|Y*)
    echo "          maildrop = ON  --enable-maildrop"
    ;;
  *)
    echo "          maildrop = OFF --disable-maildrop (default)"
    ;;
esac

echo "${CC} -O2" > cdb/conf-cc
echo "${CC} -s" > cdb/conf-ld

echo ""
echo "(Type 'make' to compile)"
echo ""
