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
char Alias[MAX_BUFF];
char Domain[MAX_BUFF];
char AliasLine[MAX_BUFF];

#define VALIAS_SELECT 0
#define VALIAS_INSERT 1
#define VALIAS_DELETE 2

int AliasAction;

void usage();
void get_options(int argc,char **argv);

int main(argc,argv)
 int argc;
 char *argv[];
{
 char *tmpalias;

	get_options(argc,argv);

	switch( AliasAction ) {
	case VALIAS_SELECT:
		if ( strstr(Email, "@") == NULL ) {
			tmpalias = valias_select_all( Alias, Email );
			while (tmpalias != NULL ) {
				printf("%s@%s -> %s\n", Alias, Email, tmpalias);
				tmpalias = valias_select_all_next(Alias);
			}
		} else {
			tmpalias = valias_select( Alias, Domain );
			while (tmpalias != NULL ) {
				printf("%s@%s -> %s\n", Alias, Domain,tmpalias);
				tmpalias = valias_select_next();
			}
		}
		break;

	case VALIAS_INSERT:
		valias_insert( Alias, Domain, AliasLine );
		break;

	case VALIAS_DELETE:
		valias_delete( Alias, Domain );
		break;

        default:
		printf("error, Alias Action is invalid %d\n", AliasAction);
		break;
	}
	exit(0);
}

void usage()
{
	printf( "valias: usage: [options] email_address \n");
	printf("options: -v ( display the vpopmail version number )\n");
	printf("         -s ( show aliases, can use just domain )\n");
	printf("         -d ( delete alias )\n");
	printf("         -i alias_line (insert alias line)\n");
}

void get_options(int argc,char **argv)
{
 int c;
 int i;
 extern char *optarg;
 extern int optind;

	memset(Alias, 0, MAX_BUFF);
	memset(Email, 0, MAX_BUFF);
	memset(Domain, 0, MAX_BUFF);
	memset(AliasLine, 0, MAX_BUFF);
	AliasAction = VALIAS_SELECT;

    	while( (c=getopt(argc,argv,"vsdi:")) != -1 ) {
		switch(c) {
		case 'v':
			printf("version: %s\n", VERSION);
			break;
		case 's':
			AliasAction = VALIAS_SELECT;
			break;
		case 'd':
			AliasAction = VALIAS_DELETE;
			break;
		case 'i':
			AliasAction = VALIAS_INSERT;
			strncpy( AliasLine, optarg, MAX_BUFF-1);
			break;
		default:
			usage();
			exit(-2);
		}
	}

	if ( optind < argc ) {
		strncpy(Email, argv[optind], MAX_BUFF);
                if ( (i = parse_email( Email, Alias, Domain, MAX_BUFF)) != 0 ) {
                  printf("Error: %s\n", verror(i));
                  vexit(i);
                }
		++optind;
	} 

	if ( Email[0] == 0 ) {
		printf("must supply alias email address\n");
		usage();
		exit(-1);
	}
}
