/*
 * vsetuserquota
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
#include <ctype.h>
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
char Quota[MAX_BUFF];
char TmpBuf1[MAX_BUFF];

void get_options(int argc,char **argv);
void usage();

int main(argc,argv)
 int argc;
 char *argv[];
{
 int i;
 static int virgin;
 struct vqpasswd *mypw;

	get_options(argc,argv);

	for(i=1;i<argc;++i){
		if ( Email[0] == 0 ) {
			strncpy( Email, argv[i], MAX_BUFF-1);
		} else {
			strncpy( Quota, argv[i], MAX_BUFF-1);
		}
	}
	lowerit(Email);

	/* check to see if email address has an @ sign in it */
	if ( strstr(Email, "@") == NULL ) {
		/* this is a domain */
		strncpy( Domain, Email, MAX_BUFF);
		virgin = 1;

		/* walk through the whole domain */
		while( (mypw=vauth_getall(Domain, virgin, 0)) != NULL ) {
			virgin = 0;
			vauth_setquota( mypw->pw_name, Domain, Quota );
		}

	/* just a single user */
	} else {
                if ( parse_email( Email, User, Domain, MAX_BUFF) != 0 ) {
                    printf("Error: %s\n", verror(i));
                    vexit(i);
                }
		vsetuserquota( User, Domain, Quota ); 
	}
	return(vexit(0));

}

void usage()
{
	printf("vsetuserquota: [options] email_address quota_in_bytes\n"); 
	printf("options:\n");
	printf("-v (print version number)\n");
}

void get_options(int argc,char **argv)
{
 int c;
 int errflag;

	memset(Email, 0, MAX_BUFF);
	memset(Quota, 0, MAX_BUFF);
	memset(Domain, 0, MAX_BUFF);
	memset(TmpBuf1, 0, MAX_BUFF);

	errflag = 0;
    while( !errflag && (c=getopt(argc,argv,"v")) != -1 ) {
		switch(c) {
			case 'v':
				printf("version: %s\n", VERSION);
				break;
			default:
				errflag = 1;
				break;
		}
	}

	if ( optind < argc ) {
		strncpy(Email, argv[optind], MAX_BUFF);
		++optind;
	}

	if ( optind < argc ) {
		strncpy(Quota, argv[optind], MAX_BUFF);
		for(c=0;Quota[c]!=0;++c){
			if ( islower((int)Quota[c]) ) {
				Quota[c] = (char)toupper((int)Quota[c]);
			}
		}
		++optind;
	}

	if ( Email[0] == 0 || Quota[0] == 0 ) { 
		usage();
		vexit(-1);
	}
}
