/*
 * vcalias
 * convert .qmail alias files into valias/mysql table
 * 
 * Copyright (C) 1999 Inter7 Internet Technologies, Inc.
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
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <dirent.h>
#include <mysql.h>
#include <vmysql.h>
#include <vpopmail.h>
#include <config.h>

MYSQL mysql;
MYSQL_RES *res = NULL;
MYSQL_ROW row;

#define SQL_BUF_SIZE 500
char SqlBuf1[500];

char *Domain;
uid_t Uid;
gid_t Gid;

#define DIR_SIZE 156
char Dir[DIR_SIZE];
char File[DIR_SIZE];

#define FILE_LINE_SIZE 1024
char FileLine[FILE_LINE_SIZE];
char EFileLine[FILE_LINE_SIZE];

#define ALIAS_NAME_SIZE 33
char AliasName[ALIAS_NAME_SIZE];

void usage();
void get_options(int argc,char **argv);

main(int argc, char **argv)
{
 DIR *mydir;
 struct dirent *mydirent;
 FILE *fs;
 char *tmpstr;
 int i,j;

	/* get the command line arguments */
	get_options(argc,argv);

	/* initialize the database structure */
	mysql_init(&mysql);

	/* open the mysql database */
	if (!(mysql_real_connect(&mysql,MYSQL_UPDATE_SERVER,
              MYSQL_UPDATE_USER,MYSQL_UPDATE_PASSWD, MYSQL_DATABASE, 
              MYSQL_PORT,NULL,0))) {
		fprintf(stderr, "Could not open database\n");
		exit(-1);
	}

	vcreate_valias_table();
	/* find the directory */
    	if ( vget_assign(Domain, Dir, DIR_SIZE, &Uid, &Gid ) == NULL ) {
		printf("could not find domain in qmail assign file\n");
		exit(-1);
	}
	printf("looking in %s directory\n", Dir);

	/* open the directory */
	if ( (mydir = opendir(Dir)) == NULL ) {
		perror("vcalias: opendir failed");
		return(-1);
	}

	/* search for .qmail files */
	while((mydirent=readdir(mydir))!=NULL){
		if ( strncmp(mydirent->d_name,".qmail-", 7)==0) {
			if ( strcmp(mydirent->d_name,".qmail-default")==0) {
				continue;
			}
			printf("found %s\n", mydirent->d_name);

			/* format the full file name */ 
			memset(File, 0, DIR_SIZE);
			strcpy( File, Dir);
			strcat( File, "/");
			strcat( File, mydirent->d_name);	

			printf("open %s\n", File);
			if ((fs=fopen(File, "r"))==NULL){
				perror("vcalias: could not open file");
				exit(-2);
			}

			memset(AliasName,0,ALIAS_NAME_SIZE);
			/* set the user name */
			for(i=7,j=0;mydirent->d_name[i]!=0;++j,++i){
				AliasName[j] = mydirent->d_name[i];
			}
			AliasName[j] = 0; 
			printf("alias name = %s\n", AliasName);

			/* read in the lines */
			memset(FileLine, 0, FILE_LINE_SIZE);
			while (fgets(FileLine, FILE_LINE_SIZE, fs) != NULL){
				/* remove the newline */
				for(i=0;FileLine[i]!='\n';++i);
				if (FileLine[i] == '\n') FileLine[i] = 0;

				printf("line = %s\n", FileLine);

				/* insert in database */
			    memset(EFileLine, 0, FILE_LINE_SIZE);
                vmysql_escape(FileLine,EFileLine);
				sprintf( SqlBuf1, "insert into valias \
( alias, domain, valias_line ) values ( \"%s\", \"%s\", \"%s\")",
				AliasName, Domain, EFileLine );

        			if (mysql_query(&mysql,SqlBuf1)) {
            				printf("insert error sql = %s\n",  
						SqlBuf1);
					exit(-1);
				}
    				res = mysql_store_result(&mysql);
    				mysql_free_result(res);

				memset(FileLine, 0, FILE_LINE_SIZE);
			}

			/* close the file */
			fclose(fs);
		}
	}
}

void get_options(int argc,char **argv)
{
 int c;
 int errflag;
 extern char *optarg;
 extern int optind;

	Domain = NULL;

	errflag = 0;
    	while( (c=getopt(argc,argv,"v")) != -1 ) {
		switch(c) {
			case 'v':
				printf("version: %s\n", VERSION);
				break;
			default:
				errflag = 1;
				break;
		}
	}

	if ( errflag == 1 ) {
		usage();
		exit(0);
	}

	if ( optind < argc ) {
		Domain = malloc(strlen(argv[optind])+1);
		strcpy( Domain, argv[optind]);
		++optind;
	} 

	if ( Domain == NULL ) {
		printf("domain not set\n");
		usage();
		exit(-1);
	}

}

void usage()
{
	printf( "vcalais: usage: domain\n"); 
	printf("         -v display the vpopmail version\n");
} 
