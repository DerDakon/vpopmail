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
char Domain[MAX_BUFF];

void usage();
void get_options(int argc,char **argv);

int main(argc,argv)
 int argc;
 char *argv[];
{
 int err;

	get_options(argc,argv);
	if ( (err=vdeldomain(Domain)) != VA_SUCCESS) {
		printf("Error: %s\n", verror(err));
	}
	return(vexit(err));
}


void usage()
{
	printf("vdeldomain: usage: [options] domain_name\n");
	printf("options: -v (print version number)\n");
}

void get_options(int argc,char **argv)
{
 int c;
 int errflag;

	memset(Domain, 0, MAX_BUFF);

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
		strncpy(Domain, argv[optind], MAX_BUFF);
		++optind;
	}

	if ( Domain[0] == 0 ) { 
		usage();
		vexit(-1);
	}
}
