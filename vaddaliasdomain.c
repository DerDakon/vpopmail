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


#define MAX_BUFF 256

char Domain_real[MAX_BUFF];
char Domain_alias[MAX_BUFF];

void usage();
void get_options(int argc,char **argv);

int main(int argc, char *argv[])
{
 int err;

    get_options(argc,argv);

    err = vaddaliasdomain( Domain_alias, Domain_real);
    if ( err != VA_SUCCESS ) {
        printf("Error: %s\n", verror(err));
	vexit(err);
    }
    return(vexit(0));
}

void usage()
{
    printf("vaddaliasdomain: usage: [options] alias_domain real_domain\n");
    printf("options: -v (print version number)\n");
}

void get_options(int argc,char **argv)
{
 int c;
 int errflag;

    memset(Domain_real, 0, sizeof(Domain_real));
    memset(Domain_alias, 0, sizeof(Domain_alias));

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
	snprintf(Domain_alias, sizeof(Domain_alias), "%s", argv[optind]);
        ++optind;
    }

    if ( optind < argc ) {
	snprintf(Domain_real, sizeof(Domain_real), "%s", argv[optind]);
        ++optind;
    }

    if ( Domain_alias[0] == 0 || Domain_real[0] == 0 ) { 
        usage();
        vexit(-1);
    }

    if ( strcmp( Domain_real, Domain_alias ) == 0 ) {
        printf("new domain and old domain are the same!\n");
        usage();
        vexit(-1);
    }
}
