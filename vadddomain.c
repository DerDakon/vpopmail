/*
 * vadddomain
 * part of the vpopmail package
 * 
 * Copyright (C) 1999,2001 Inter7 Internet Technologies, Inc.
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

char Domain[MAX_BUFF];
char Passwd[MAX_BUFF];
char User[MAX_BUFF];
char Dir[MAX_BUFF];
char Quota[MAX_BUFF];
char BounceEmail[MAX_BUFF];
char TmpBuf1[MAX_BUFF];
char a_dir[MAX_BUFF];
int  Apop;
int  Bounce;
int  RandomPw;
uid_t Uid;
gid_t Gid;
uid_t a_uid;
gid_t a_gid;

int usage();
void get_options(int argc,char **argv);

int main(argc,argv)
 int argc;
 char *argv[];
{
 int err;
 FILE *fs;

    get_options(argc,argv);

    if ( strlen(Passwd) <= 0 ) { 
        strncpy( Passwd, vgetpasswd("postmaster"), MAX_BUFF);
    }

    if ( (err=vadddomain(Domain,Dir,Uid,Gid)) != VA_SUCCESS ) {
        printf("Error: %s\n", verror(err));
        vexit(err);
    }

    if ((err=vadduser("postmaster", Domain, Passwd, "Postmaster", Apop )) != 
        VA_SUCCESS ) {
        printf("Error: %s\n", verror(err));
        vexit(err);
    }

    if ( Quota[0] != 0 ) {
        vsetuserquota( "postmaster", Domain, Quota ); 
    }
    if ( BounceEmail[0] != 0 ) {
        if ( strstr(BounceEmail, "@") != NULL ) { 
            vget_assign(Domain, a_dir, 156, &a_uid, &a_gid );
            snprintf(TmpBuf1, MAX_BUFF, "%s/.qmail-default", a_dir);
            if ( (fs = fopen(TmpBuf1, "w+"))!=NULL) {
                fprintf(fs, "| %s/bin/vdelivermail '' %s\n", VPOPMAILDIR, 
                    BounceEmail);
                fclose(fs);
                chown(TmpBuf1, a_uid, a_gid);
            } else {
                printf("Error: could not open %s\n", TmpBuf1);
            }
        } else {
            printf("Invalid bounce email address %s\n", BounceEmail);
        }
    }
    if ( RandomPw == 1 ) printf("Random password: %s\n", Passwd );
    
    return(vexit(0));
}

int usage()
{
	printf("vadddomain: usage: vadddomain [options] virtual_domain [postmaster password]\n");
	printf("options: -v prints the version\n");
	printf("         -q quota_in_bytes (sets the quota for postmaster account)\n");
	printf("         -b (bounces all mail that doesn't match a user, default)\n");
	printf("         -e email_address (forwards all non matching user to this address)\n");
	printf("         -u user (sets the uid/gid based on a user in /etc/passwd)\n");
	printf("         -d dir (sets the dir to use for this domain)\n");
	printf("         -i uid (sets the uid to use for this domain)\n");
	printf("         -g gid (sets the gid to use for this domain)\n");
	printf("         -a sets the account to use APOP, default is POP\n");
	printf("         -O optimize adding, for bulk adds set this for all\n");
	printf("            except the last one\n");
	printf("         -r generate a random password for postmaster\n");
	exit(0);
}

void get_options(int argc,char **argv)
{
 int c;
 int errflag;
 struct passwd *mypw;
 extern char *optarg;
 extern int optind;

    memset(Domain, 0, MAX_BUFF);
    memset(Passwd, 0, MAX_BUFF);
    memset(Quota, 0, MAX_BUFF);
    memset(Dir, 0, MAX_BUFF);
    memset(BounceEmail, 0, MAX_BUFF);
    memset(TmpBuf1, 0, MAX_BUFF);
    Uid = VPOPMAILUID;
    Gid = VPOPMAILGID;
    Apop = USE_POP;
    Bounce = 1;
    RandomPw = 0;

    errflag = 0;
    while( !errflag && (c=getopt(argc,argv,"aq:be:u:vi:g:d:Or")) != -1 ) {
	switch(c) {
	case 'v':
	    printf("version: %s\n", VERSION);
	    break;
	case 'd':
	    strncpy(Dir,optarg,MAX_BUFF);
	    break;
	case 'u':
	    strncpy(User,optarg,MAX_BUFF);
	    break;
	case 'q':
	    strncpy(Quota,optarg,MAX_BUFF);
	    break;
	case 'e':
	    strncpy(BounceEmail,optarg,MAX_BUFF);
	    break;
	case 'i':
	    Uid = atoi(optarg);
	    break;
	case 'g':
	    Gid = atoi(optarg);
	    break;
	case 'b':
	    Bounce = 1;
	    break;
	case 'a':
	    Apop = USE_APOP;
	    break;
	case 'O':
            OptimizeAddDomain = 1;
	    break;
        case 'r':
            RandomPw = 1;
            strcpy( Passwd, vgen_pass(8));
            break;
	default:
	    errflag = 1;
	    break;
	}
    }

    if ( optind < argc ) {
	strncpy(Domain, argv[optind], MAX_BUFF);
	++optind;
    }

    if ( optind < argc ) {
	strncpy(Passwd, argv[optind], MAX_BUFF);
	++optind;
    }

    if ( User[0] != 0 ) {
	if ( (mypw = getpwnam(User)) != NULL ) {
	    if ( Dir[0] == 0 ) {
		strncpy(Dir, mypw->pw_dir, MAX_BUFF);
	    }
	    Uid = mypw->pw_uid;
	    Gid = mypw->pw_gid;
	} else {
	    printf("Error: user %s not found in /etc/passwd\n", User);
	    exit(-1);
	}
    }
    if ( Dir[0] == 0 ) strncpy(Dir, VPOPMAILDIR, MAX_BUFF);
    if ( Domain[0] == 0 ) usage();
}
