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
char Passwd[MAX_BUFF];
char Quota[MAX_BUFF];
char Gecos[MAX_BUFF];
char EncryptedPasswd[MAX_BUFF];
char TmpBuf1[MAX_BUFF];
int apop;
int RandomPw;
int NoPassword = 0;

void usage();
void get_options(int argc,char **argv);

int main(int argc,char **argv)
{
 int i;
 struct vqpasswd *vpw;

    get_options(argc,argv);

    for(i=0;i<MAX_BUFF;++i) {
      User[i] = 'x';
      Domain[i] = 'x';
    }

    /* parse the email address into user and domain */
    if ( (i=parse_email( Email, User, Domain, MAX_BUFF)) != 0 ) {
        printf("Error: %s\n", verror(i));
        vexit(i);
    }

    if ( Domain[0] == 0 ) {
      printf("You did not use a full email address for the user name\n");
      printf("Only full email addresses should be used\n");
      vexit(-1);
    }

    /* if the comment field is blank use the user name */
    if ( Gecos[0] == 0 ) strncpy(Gecos, User, MAX_BUFF);

    /* get the password if not set on command line */
    if ( NoPassword == 0 ) {
        if ( strlen(Passwd) <= 0 ) {
            strncpy(Passwd,vgetpasswd(Email),MAX_BUFF);
        }

        if ( strlen(Passwd) <= 0 ) {
            printf("Please input password\n");
            usage();
            exit(-1);
        }
    }

    /* add the user */
    if ( (i=vadduser(User, Domain, Passwd, Gecos, apop )) < 0 ) {
        printf("Error: %s\n", verror(i));
        vexit(i);
    }

    /* set the users quota if set on the command line */
    if ( Quota[0] != 0 ) vsetuserquota( User, Domain, Quota ); 

    /* Check for encrypted password */
    if ( EncryptedPasswd[0] != 0 ) {
        vpw = vauth_getpw( User,Domain);
        vpw->pw_passwd = EncryptedPasswd;
        vauth_setpw( vpw, Domain);
    }
    if ( RandomPw == 1 ) printf("Random password: %s\n", Passwd );

    return(vexit(0));
}


void usage()
{
    printf( "vadduser: usage: [options] email_address [passwd]\n");
    printf("options: -v (print the version)\n");
    printf("         -q quota_in_bytes (sets the users quota)\n");
    printf("         -s (don't rebuild the vpasswd.cdb file, faster for large sites)\n");
    printf("         -c comment (sets the gecos comment field)\n");
    printf("         -e standard_encrypted_password\n");
    printf("         -n no_password\n");
    printf("         -r generate a random password\n");
}

void get_options(int argc,char **argv)
{
 int c;
 int errflag;
 extern char *optarg;
 extern int optind;

    memset(Email, 0, MAX_BUFF);
    memset(Passwd, 0, MAX_BUFF);
    memset(Domain, 0, MAX_BUFF);
    memset(Quota, 0, MAX_BUFF);
    memset(EncryptedPasswd, 0, MAX_BUFF);
    memset(TmpBuf1, 0, MAX_BUFF);
    apop = USE_POP; 
    RandomPw = 0;

    errflag = 0;
    while( !errflag && (c=getopt(argc,argv,"svc:nq:e:r")) != -1 ) {
        switch(c) {
          case 'v':
            printf("version: %s\n", VERSION);
            break;
          case 'c':
            strncpy( Gecos, optarg, MAX_BUFF-1);
            break;
          case 'q':
            strncpy( Quota, optarg, MAX_BUFF-1);
            break;
          case 'e':
            strncpy( EncryptedPasswd, optarg, MAX_BUFF-1);
            break;
          case 's':
            NoMakeIndex = 1;
            break;
          case 'n':
            NoPassword = 1;
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

    if ( optind < argc  ) {
        strncpy(Email, argv[optind], MAX_BUFF);
        ++optind;
    }

    if ( (NoPassword == 0) && (optind < argc) ) {
        strncpy(Passwd, argv[optind], MAX_BUFF);
        ++optind;
    }

    if ( Email[0] == 0 ) { 
        usage();
        exit(-1);
    }
}
