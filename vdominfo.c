/*
 * Copyright (C) 2001,2002 Inter7 Internet Technologies, Inc.
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
#include <memory.h>
#include "config.h"
#include "vpopmail.h"
#include "vauth.h"


#define MAX_BUFF 500
char Domain[MAX_BUFF];
char Dir[MAX_BUFF];
char TmpBuf[MAX_BUFF];
uid_t Uid;
gid_t Gid;

int DisplayName;
int DisplayUid;
int DisplayGid;
int DisplayDir;
int DisplayAll;
int DisplayTotalUsers;

void usage();
void get_options(int argc, char **argv);
void display_domain(char *domain, char *dir, uid_t uid, gid_t gid);
void display_all_domains();

#define TOKENS ":\n"

extern vdir_type vdir;

int main(argc,argv)
 int argc;
 char *argv[];
{
    get_options(argc,argv);

    if (Domain[0] != 0 ) {
        if ( vget_assign(Domain, Dir, 156, &Uid, &Gid ) == NULL ) {
            printf("domain %s does not exist\n", Domain );
            vexit(-1);
        }
        display_domain(Domain, Dir, Uid, Gid);
    } else {
        display_all_domains();
    }
    return(vexit(0));
}

void usage()
{
    printf("vdominfo: usage: [options] [domain]\n");
    printf("options: -v (print version number)\n");
    printf("         -a (display all fields, this is the default)\n");
    printf("         -n (display domain name)\n");
    printf("         -u (display uid field)\n");
    printf("         -g (display gid field)\n");
    printf("         -d (display domain directory)\n");
    printf("         -t (display total users)\n");
}

void get_options(int argc, char **argv)
{
 int c;
 int errflag;
 extern int optind;

    DisplayName = 0;
    DisplayUid = 0;
    DisplayGid = 0;
    DisplayDir = 0;
    DisplayTotalUsers = 0;
    DisplayAll = 1;

    memset(Domain, 0, MAX_BUFF);

    errflag = 0;
    while( !errflag && (c=getopt(argc,argv,"vanugdt")) != -1 ) {
        switch(c) {
            case 'v':
                printf("version: %s\n", VERSION);
                break;
            case 'n':
                DisplayName = 1;    
                DisplayAll = 0;
                break;
            case 'u':
                DisplayUid = 1;    
                DisplayAll = 0;
                break;
            case 'g':
                DisplayGid = 1;    
                DisplayAll = 0;
                break;
            case 'd':
                DisplayDir = 1;    
                DisplayAll = 0;
                break;
            case 't':
                DisplayTotalUsers = 1;    
                DisplayAll = 0;
                break;
            case 'a':
                DisplayAll = 0;
                break;
            default:
                errflag = 1;
                break;
        }
    }

    if ( errflag > 0 ) {
        usage();
        vexit(-1);
    }

    if ( optind < argc ) { 
        strncpy(Domain, argv[optind], MAX_BUFF);
        ++optind;
    }
}

void display_domain(char *domain, char *dir, uid_t uid, gid_t gid)
{
    if ( DisplayAll ) {
        printf("domain: %s\n", domain); 
        printf("uid:    %lu\n", (long unsigned)uid);
        printf("gid:    %lu\n", (long unsigned)gid);
        printf("dir:    %s\n",  dir);
        open_big_dir(domain, uid, gid);
        printf("users:  %lu\n",  vdir.cur_users);
        close_big_dir(domain,uid,gid);
    } else {
        if ( DisplayName ) printf("%s\n", domain); 
        if ( DisplayUid ) printf("%lu\n", (long unsigned)uid);
        if ( DisplayGid ) printf("%lu\n", (long unsigned)gid);
        if ( DisplayDir ) printf("%s\n",  dir);
        if ( DisplayTotalUsers ) {
            open_big_dir(domain, uid, gid);
            printf("%lu\n",  vdir.cur_users);
            close_big_dir(domain,uid,gid);
        }
    }
}

void display_all_domains()
{
 FILE *fs;
 char *tmpstr;

    snprintf(TmpBuf, MAX_BUFF, "%s/users/assign", QMAILDIR);
    if ((fs=fopen(TmpBuf, "r"))==NULL) {
        printf("could not open assign file %s\n", TmpBuf);
    }

    while( fgets(TmpBuf, MAX_BUFF, fs) != NULL ) {
	if ( (tmpstr=strtok(TmpBuf, TOKENS)) == NULL ) continue;

	if ( (tmpstr=strtok(NULL, TOKENS)) == NULL ) continue;
	strncpy( Domain, tmpstr, MAX_BUFF);

	if ( (tmpstr=strtok(NULL, TOKENS)) == NULL ) continue;
	Uid = atol(tmpstr);

	if ( (tmpstr=strtok(NULL, TOKENS)) == NULL ) continue;
	Gid = atol(tmpstr);

	if ( (tmpstr=strtok(NULL, TOKENS)) == NULL ) continue;
	strncpy( Dir, tmpstr, MAX_BUFF);

	display_domain(Domain, Dir, Uid, Gid);
    }
    fclose(fs);
}

