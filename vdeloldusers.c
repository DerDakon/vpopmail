/*
 * vdeloldusers
 * remove a user who has not authenticated in a long time.
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
#include <time.h>

#include "config.h"
#include "vpopmail.h"
#include "vauth.h"
#ifdef USE_MYSQL
#include <mysql.h>
#include "vmysql.h"
#endif

#ifndef ENABLE_AUTH_LOGGING
int main()
{
	printf("auth logging was not enabled, reconfigure with --enable-auth-logging=y\n");
	return(vexit(-1));
}
#else
#ifndef USE_MYSQL 
int main()
{
	printf("vdeloldusers currently does not work without the mysql module\n");
	return(vexit(-1));
}
#else



#define MAX_BUFF     500
#define DEFAULT_AGE  180

char Domain[MAX_BUFF];
char SqlBuf[MAX_BUFF];
int  Age;
int  EveryDomain;
int  ReportOnly;

#ifdef USE_MYSQL
static MYSQL mysql;
static MYSQL_RES *res = NULL;
static MYSQL_ROW row;
#endif

void usage();
void get_options(int argc,char **argv);

int main(argc,argv)
 int argc;
 char *argv[];
{
 time_t nowt;

	get_options(argc,argv);

	/* get the time */
	nowt = time(NULL);

	/* subtract the age */
	nowt = nowt - (86400*Age);

	mysql_init(&mysql);
	if (!(mysql_real_connect(&mysql,MYSQL_UPDATE_SERVER,
	MYSQL_UPDATE_USER,MYSQL_UPDATE_PASSWD,
			MYSQL_DATABASE, 0,NULL,0))) {
		printf("could not connect to mysql database\n");
		vexit(-1);
	}

	snprintf(SqlBuf, MAX_BUFF, 
    "select user,domain from lastauth where timestamp < '%lu'",
       nowt); 

	if (mysql_query(&mysql,SqlBuf)) {
		printf("error in mysql query %s\n", SqlBuf);
		vexit(-1);
	}
	if (!(res = mysql_use_result(&mysql))) {
		printf("vsql_getpw: store result failed\n");
		vexit(-1);	
	}
	while((row = mysql_fetch_row(res))) {
          if ( strcmp(row[0], "postmaster") == 0 ) {
            printf("don't delete postmaster account\n");
          } else {
            if ( ReportOnly == 0 )  vdeluser( row[0], row[1]);
            printf("%s %s\n", row[0], row[1]);
          }
	}
	mysql_free_result(res);
	vexit(0);
}


void usage()
{
	printf("vdeloldusers: usage: [options]\n");
	/*printf("options: -d domain\n");*/
	printf("options: -a age_in_days (will delete accounts older than this date)\n");
	printf("                        (default is 6 months or 180 days)\n");
	printf("         -v (print version number)\n");
	printf("         -e (process every domain)\n");
        printf("         -r (report only, don't delete)\n");
}

void get_options(int argc,char **argv)
{
 int c;
 int errflag;

	memset(Domain, 0, MAX_BUFF);
	Age = DEFAULT_AGE;
        EveryDomain = 0;
        ReportOnly = 0;

	errflag = 0;
	while( !errflag && (c=getopt(argc,argv,"vd:a:er")) != -1 ) {
		switch(c) {
			case 'e':
                                EveryDomain = 1;
				break;
			case 'r':
                                ReportOnly = 1;
				break;
			case 'd':
				strncpy(Domain, optarg, MAX_BUFF);
				break;
			case 'a':
				Age = atoi(optarg);
				break;
			case 'v':
				printf("version: %s\n", VERSION);
				break;
			default:
				errflag = 1;
				break;
		}
	}

	if (errflag == 1 || EveryDomain == 0 ) {
		usage();
		vexit(-1);
	}
}
#endif
#endif
