/*
 * $Id: vdominfo.c,v 1.4 2004-03-14 18:00:40 kbo Exp $
 * Copyright (C) 2001-2004 Inter7 Internet Technologies, Inc.
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


#define MAX_BUFF 256
char Domain[MAX_BUFF];
char Dir[MAX_BUFF];
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

int main(int argc, char *argv[])
{
    get_options(argc,argv);

    /* did we want to view a single domain domain? */
    if (Domain[0] != 0 ) {
        /* yes, just lookup a single domain */
        if ( vget_assign(Domain, Dir, sizeof(Dir), &Uid, &Gid ) == NULL ) {
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

    memset(Domain, 0, sizeof(Domain));

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
	snprintf(Domain, sizeof(Domain), "%s", argv[optind]); 
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
 char TmpBuf[MAX_BUFF];
 char RealName[MAX_BUFF];

    snprintf(TmpBuf, sizeof(TmpBuf), "%s/users/assign", QMAILDIR);
    if ((fs=fopen(TmpBuf, "r"))==NULL) {
        printf("could not open assign file %s\n", TmpBuf);
        vexit(-1);
    }

    /* users/assign looks like
     * +alias.domain.com-:real.domain.com:89:89:/var/vpopmail/domains/real.domain.com:-::
     */

    while( fgets(TmpBuf, sizeof(TmpBuf), fs) != NULL ) {

        /* skip over any lines that do not contain tokens */
	if ( (tmpstr=strtok(TmpBuf, TOKENS)) == NULL ) continue;

	/* ignore lines that don't start with "+" */
	if (*tmpstr != '+') continue;

	/* suck out the "alias name" of the domain 
         * (we have to drop the leading '+' and the trailing "-") 
         */
	snprintf(Domain, sizeof(Domain), "%s", tmpstr+1);
        Domain[strlen(Domain)-1] = 0;

	/* ignore domains without '.' in them (non-vpopmail entries */
	if (strchr (Domain, '.') == NULL) continue;

        /* jump over the token between the alias and real domain */
	if ( (tmpstr=strtok(NULL, TOKENS)) == NULL ) continue;

        /* suck out the "real name" of the domain */
	snprintf(RealName, sizeof(RealName), "%s", tmpstr);

	/* jump over the token between real domain and uid */
	if ( (tmpstr=strtok(NULL, TOKENS)) == NULL ) continue;

	/* suck out the uid */
	Uid = atol(tmpstr);

	/* jump over the token between the uid and the gid */
	if ( (tmpstr=strtok(NULL, TOKENS)) == NULL ) continue;

	/* suck out the gid */
	Gid = atol(tmpstr);

	/* jump over the token between the gid and the dir */
	if ( (tmpstr=strtok(NULL, TOKENS)) == NULL ) continue;

        /* suck out the dir */
	snprintf(Dir, sizeof(Dir), "%s", tmpstr);

	display_domain(Domain, Dir, Uid, Gid);

	if (strcmp(Domain, RealName) != 0) {
 		printf ("Note:   %s is an alias for %s\n",Domain,RealName);
	}
     
	printf ("\n");
    }
    fclose(fs);
}

