/*
 * Copyright (C) 1999-2002 Inter7 Internet Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include "config.h"
#include "vpopmail.h"
#include "vauth.h"


#define MAX_BUFF 500

char Email[MAX_BUFF];
char User[MAX_BUFF];
char Domain[MAX_BUFF];
char Gecos[MAX_BUFF];
char Dir[MAX_BUFF];
char Passwd[MAX_BUFF];
char Quota[MAX_BUFF];
char Crypted[MAX_BUFF];

int GidFlag = 0;
int QuotaFlag = 0;
int ClearFlags;

void usage();
void get_options(int argc,char **argv);

int main(argc,argv)
 int argc;
 char *argv[];
{
 int i; 
 static int virgin = 1;
 struct vqpasswd *mypw;

    get_options(argc,argv);

    /* a single email address */
    if ( strstr(Email, "@") != NULL ) {
        if ( (i = parse_email( Email, User, Domain, MAX_BUFF)) != 0 ) {
            printf("Error: %s\n", verror(i));
            vexit(i);
        }

        if ( (mypw = vauth_getpw( User, Domain )) == NULL ) {
            printf("no such user %s@%s\n", User, Domain);
            vexit(-1);
        }
        
        if ( Gecos[0] != 0 ) mypw->pw_gecos = Gecos;
        if ( Dir[0] != 0 ) mypw->pw_dir = Dir;
        if ( Passwd[0] != 0 )  {
            mkpasswd3(Passwd,Crypted, 100);
            mypw->pw_passwd = Crypted;
#ifdef CLEAR_PASS
            mypw->pw_clear_passwd = Passwd;
#endif
        } else if ( Crypted[0] != 0 ) {
            mypw->pw_passwd = Crypted;
        }
        if ( ClearFlags == 1 ) mypw->pw_gid = 0; 
        if ( GidFlag != 0 ) mypw->pw_gid |= GidFlag; 
        if ( QuotaFlag == 1 ) {
            mypw->pw_shell = Quota;
            remove_maildirsize(mypw->pw_dir);
        }
        if ( (i=vauth_setpw( mypw, Domain )) != 0 ) {
            printf("Error: %s\n", verror(i));
            vexit(i);
        }
    } else {
        virgin = 1;
        while( (mypw=vauth_getall(Email, virgin, 0)) != NULL ) {
            virgin = 0;

            if ( Gecos[0] != 0 ) mypw->pw_gecos = Gecos;
            if ( Dir[0] != 0 ) mypw->pw_dir = Dir;
            if ( Passwd[0] != 0 )  {
                mkpasswd3(Passwd,Crypted, 100);
                mypw->pw_passwd = Crypted;
#ifdef CLEAR_PASS
                mypw->pw_clear_passwd = Passwd;
#endif
            } else if ( Crypted[0] != 0 ) {
                mypw->pw_passwd = Crypted;
            }
            if ( ClearFlags == 1 ) mypw->pw_gid = 0; 
            if ( GidFlag != 0 ) mypw->pw_gid |= GidFlag; 
            if ( QuotaFlag == 1 ) {
                mypw->pw_shell = Quota;
                remove_maildirsize(mypw->pw_dir);
            }
            if ( (i=vauth_setpw( mypw, Email )) != 0 ) {
                printf("Error: %s\n", verror(i));
                vexit(i);
            }
        }
    }
    return(vexit(0));

}

void usage()
{
    printf( "vmoduser: usage: [options] email_addr or domain ( for the entire domain )\n");
    printf("options: -v ( display the vpopmail version number )\n");
    printf("         -n ( don't rebuild the vpasswd.cdb file )\n");
    printf("         -q quota ( set quota )\n");
    printf("         -c comment (set the comment/gecos field )\n");
    printf("         -e encrypted_passwd (set the password field )\n");
    printf("         -C clear_text_passwd (set the password field )\n");
    printf("the following options are bit flags in the gid int field\n");
    printf("         -u ( set no dialup flag )\n");
    printf("         -d ( set no password changing flag )\n");
    printf("         -p ( set no pop access flag )\n");
    printf("         -s ( set no smtp access flag )\n");
    printf("         -w ( set no web mail access flag )\n");
    printf("         -i ( set no imap access flag )\n");
    printf("         -b ( set bounce mail flag )\n");
    printf("         -r ( set no external relay flag )\n");
    printf("         -a ( grant qmailadmin administrator privileges)\n");
    printf("         -0 ( set V_USER0 flag )\n"); 
    printf("         -1 ( set V_USER1 flag )\n"); 
    printf("         -2 ( set V_USER2 flag )\n"); 
    printf("         -3 ( set V_USER3 flag )\n"); 
    printf("         -x ( clear all flags )\n");

}

void get_options(int argc,char **argv)
{
 int c;
 int errflag;
 extern char *optarg;
 extern int optind;
 double q;
 int i;

    memset(User, 0, MAX_BUFF);
    memset(Email, 0, MAX_BUFF);
    memset(Domain, 0, MAX_BUFF);
    memset(Gecos, 0, MAX_BUFF);
    memset(Dir, 0, MAX_BUFF);
    memset(Passwd, 0, MAX_BUFF);
    memset(Crypted, 0, MAX_BUFF);
    memset(Quota, 0, MAX_BUFF);
    ClearFlags = 0;
    QuotaFlag = 0;
    NoMakeIndex = 0;

    errflag = 0;
    while( (c=getopt(argc,argv,"D:avunxc:q:dpswibr0123he:C:")) != -1 ) {
        switch(c) {
            case 'v':
                printf("version: %s\n", VERSION);
                break;
            case 'n':
                NoMakeIndex = 1;
                break;
            case 'x':
                ClearFlags = 1;
                break;
            case 'e':
                strncpy( Crypted, optarg, MAX_BUFF-1);
                break;
            case 'C':
                strncpy( Passwd, optarg, MAX_BUFF-1);
                break;
            case 'D':
                strncpy( Dir, optarg, MAX_BUFF-1);
		break;
            case 'c':
                strncpy( Gecos, optarg, MAX_BUFF-1);
                break;
            case 'q':
                QuotaFlag = 1;
		/* properly handle the following formats:
		 * "1M", "1024K", "1048576" (set 1 MB quota)
		 * "NOQUOTA" (no quota)
		 * "1048576S,1000C" (1 MB size, 1000 message limit)
		 */
                strncpy( Quota, optarg, MAX_BUFF-1);
		i = strlen (Quota);
	        q = atof(Quota);
		if ((Quota[i-1] == 'M') || (Quota[i-1] == 'm')) {
		    sprintf (Quota, "%.0fS", q * 1024 * 1024);
		} else if ((Quota[i-1] == 'K') || (Quota[i-1] == 'k')) {
		    sprintf (Quota, "%.0fS", q * 1024);
		} else if ((Quota[i-1] == 'S') || (Quota[i-1] == 's') ||
		    (Quota[i-1] == 'C') || (Quota[i-1] == 'c')) {
		    /* don't make any changes */
		} else if (q > 0) {
		    sprintf (Quota, "%.0fS", q);
		} /* else don't make any changes */
                break;
            case 'd':
                GidFlag |= NO_PASSWD_CHNG;
                break;
            case 'p':
                GidFlag |= NO_POP;
                break;
            case 's':
                GidFlag |= NO_SMTP;
                break;
            case 'w':
                GidFlag |= NO_WEBMAIL;
                break;
            case 'i':
                GidFlag |= NO_IMAP;
                break;
            case 'b':
                GidFlag |= BOUNCE_MAIL;
                break;
            case 'r':
                GidFlag |= NO_RELAY;
                break;
            case 'u':
                GidFlag |= NO_DIALUP;
                break;
            case '0':
                GidFlag |= V_USER0;
                break;
            case '1':
                GidFlag |= V_USER1;
                break;
            case '2':
                GidFlag |= V_USER2;
                break;
            case '3':
                GidFlag |= V_USER3;
                break;
            case 'a':
                GidFlag |= QA_ADMIN;
                break;
            case 'h':
                usage();
                vexit(0);
            default:
                errflag = 1;
                break;
        }
    }

    if ( optind < argc ) {
        strncpy(Email, argv[optind], MAX_BUFF);
        ++optind;
    }

    if ( Email[0] == 0 ) { 
        usage();
        vexit(-1);
    }
}
