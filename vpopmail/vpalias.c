#ifndef VALIAS 
/*
 * $Id: vpalias.c,v 1.5 2004-01-14 05:39:41 tomcollins Exp $
 * Copyright (C) 2000-2002 Inter7 Internet Technologies, Inc.
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
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include "config.h"
#include "vpopmail.h"
#include "vauth.h"

/* Globals */
static char alias_line[MAX_ALIAS_LINE];
static DIR *mydir = NULL;
static char Dir[156];

#define MAX_FILE_SIZE 156
static char FileName[156];
static FILE *alias_fs = NULL;

/* forward declarations */
char *valias_next_return_line(char *alias);

char *valias_select( char *alias, char *domain )
{
 char *tmpstr;
 char tmpbuf[156];
 uid_t uid;
 gid_t gid;
 int i;
 char *p;

    if ( alias == NULL )  { 
      verrori=VA_NULL_POINTER;  
      return( NULL );
    }

    if ( domain == NULL ) { 
      verrori=VA_NULL_POINTER;
      return( NULL );
    }

    if ( strlen(alias) >= MAX_PW_NAME ) {
      verrori = VA_USER_NAME_TOO_LONG;
      return( NULL );
    }

    if ( strlen(domain) >= MAX_PW_DOMAIN ) {
      verrori = VA_DOMAIN_NAME_TOO_LONG;
      return( NULL );
    }

    if ( alias_fs != NULL ) fclose(alias_fs);

    if ((tmpstr=vget_assign(domain,alias_line,MAX_ALIAS_LINE,&uid,&gid))==NULL) {
	printf("invalid domain, not in qmail assign file\n");
	return(NULL);
    }
    /* need to convert '.' to ':' */
    i = snprintf(tmpbuf, sizeof(tmpbuf), "%s/.qmail-", tmpstr);
    for (p = alias; (i < sizeof(tmpbuf) - 1) && (*p != '\0'); p++)
      tmpbuf[i++] = (*p == '.' ? ':' : *p);
    tmpbuf[i] = '\0';
    if ( (alias_fs = fopen(tmpbuf, "r")) == NULL ) {
    	return(NULL);
    }
    return(valias_select_next());
}

char *valias_select_next()
{
 char *tmpstr;

    if ( alias_fs == NULL ) return(NULL);
    memset(alias_line,0,sizeof(alias_line));

    if ( fgets(alias_line, sizeof(alias_line), alias_fs) == NULL ) {
	fclose(alias_fs);
	alias_fs = NULL;
	return(NULL);
    }
    for(tmpstr=alias_line;*tmpstr!=0;++tmpstr) {
	if ( *tmpstr == '\n') *tmpstr = 0;
    }
    return(alias_line);
}

int valias_insert( char *alias, char *domain, char *alias_line)
{
 int i;
 char *tmpstr;
 char Dir[156];
 uid_t uid;
 gid_t gid;
 FILE *fs;

    if ( alias == NULL ) return(VA_NULL_POINTER);
    if ( domain == NULL ) return(VA_NULL_POINTER);
    if ( alias_line == NULL ) return(VA_NULL_POINTER);
    if ( strlen(alias) >= MAX_PW_NAME ) return(VA_USER_NAME_TOO_LONG);
    if ( strlen(domain) >= MAX_PW_DOMAIN ) return(VA_DOMAIN_NAME_TOO_LONG);
    if ( strlen(alias_line) >= MAX_ALIAS_LINE ) return(VA_ALIAS_LINE_TOO_LONG);

    if ((tmpstr = vget_assign(domain, Dir, sizeof(Dir), &uid, &gid )) == NULL) {
	printf("invalid domain, not in qmail assign file\n");
	return(-1);
    }
    strncat(Dir, "/.qmail-", sizeof(Dir)-strlen(Dir)-1);
    for(i=0;alias[i]!=0;++i) if ( alias[i] == '.' ) alias[i] = ':';
    strncat(Dir, alias, sizeof(Dir)-strlen(Dir)-1);
	
    if ( (fs = fopen(Dir, "a")) == NULL ) {
	return(-1);
    }
    chmod(Dir,0600);
    chown(Dir,uid,gid);

    fprintf(fs, "%s\n", alias_line);
    fclose(fs);
    return(0);
}

int valias_remove( char *alias, char *domain, char *alias_line)
{
  fprintf (stderr, "Error: valias_remove() not implemented for non-SQL backends.\n");
  return -1;
}

int valias_delete( char *alias, char *domain)
{
 char *tmpstr;
 char Dir[156];
 uid_t uid;
 gid_t gid;
 int i;

    if ( alias == NULL ) return(VA_NULL_POINTER); 
    if ( domain == NULL ) return(VA_NULL_POINTER);
    if ( strlen(alias) >= MAX_PW_NAME ) return(VA_USER_NAME_TOO_LONG);
    if ( strlen(domain) >= MAX_PW_DOMAIN ) return(VA_DOMAIN_NAME_TOO_LONG);

    if ((tmpstr = vget_assign(domain, Dir, 156, &uid, &gid )) == NULL) {
	printf("invalid domain, not in qmail assign file\n");
	return(-1);
    }
    strncat(Dir, "/.qmail-", sizeof(Dir)-strlen(Dir)-1);
    for(i=0;alias[i]!=0;++i) if ( alias[i] == '.' ) alias[i] = ':';
    strncat(Dir, alias, sizeof(Dir)-strlen(Dir)-1);
    return(unlink(Dir));
}

char *valias_select_all( char *alias, char *domain )
{
 uid_t uid;
 gid_t gid;

    if ( alias == NULL )  { 
      verrori=VA_NULL_POINTER;  
      return( NULL );
    }

    if ( domain == NULL ) { 
      verrori=VA_NULL_POINTER;
      return( NULL );
    }
  
    if ( strlen(alias) >= MAX_PW_NAME ) {
      verrori = VA_USER_NAME_TOO_LONG;
      return( NULL );
    }

    if ( strlen(domain) >= MAX_PW_DOMAIN ) {
      verrori = VA_DOMAIN_NAME_TOO_LONG;
      return( NULL );
    }

    if ( alias_fs != NULL ) {
	fclose(alias_fs); 
        alias_fs = NULL;
    }

    if ((vget_assign(domain, Dir, sizeof(Dir), &uid, &gid )) == NULL) {
	printf("invalid domain, not in qmail assign file\n");
	return(NULL);
    }

    if (mydir!=NULL) closedir(mydir);
    if ( (mydir = opendir(Dir)) == NULL ) return(NULL);

    return(valias_select_all_next(alias));
}

char *valias_select_all_next(char *alias)
{
 static struct dirent *mydirent;
 char *tmpstr;
 int i;

    if ( alias == NULL )  { 
      verrori=VA_NULL_POINTER;  
      return( NULL );
    }
  
    if ( strlen(alias) >= MAX_PW_NAME ) {
      verrori = VA_USER_NAME_TOO_LONG;
      return( NULL );
    }


    if ( alias_fs != NULL ) {
    	if ( fgets(alias_line, sizeof(alias_line),alias_fs)==NULL){
		fclose(alias_fs); alias_fs = NULL;
    	} else {
    		for(tmpstr=alias_line;*tmpstr!=0;++tmpstr) {
			if ( *tmpstr == '\n') *tmpstr = 0;
    		}
		/* Michael Bowe 21st Aug 2003
		 * Chance of buffer overflow here,
                 * because we dont know the size of alias
                 */
		strcpy(alias, &mydirent->d_name[7]);
                for(i=0;alias[i]!=0;++i) if (alias[i]==':') alias[i]='.';
    		return(alias_line);
	}
    }

    while((mydirent=readdir(mydir))!=NULL){
        if ( strncmp(mydirent->d_name,".qmail-", 7) == 0 &&
             strcmp(mydirent->d_name, ".qmail-default") != 0 ) {
		snprintf(FileName, sizeof(FileName), "%s/%s", Dir, mydirent->d_name);
    		if ( (alias_fs = fopen(FileName, "r")) == NULL ) {
    			return(NULL);
    		}
    		if ( fgets(alias_line, sizeof(alias_line),alias_fs)==NULL){
			fclose(alias_fs); alias_fs = NULL;
			continue;
    		}
    		for(tmpstr=alias_line;*tmpstr!=0;++tmpstr) {
			if ( *tmpstr == '\n') *tmpstr = 0;
    		}
                /* Michael Bowe 21st Aug 2003
                 * Chance of buffer overflow here,
                 * because we dont know the size of alias
                 */
		strcpy(alias, &mydirent->d_name[7]);
                for(i=0;alias[i]!=0;++i) if (alias[i]==':') alias[i]='.';
    		return(alias_line);
	}
    }
    closedir(mydir); mydir=NULL;
    return(NULL);
}
#endif
