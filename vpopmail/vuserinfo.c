/*
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
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include "config.h"
#ifdef ENABLE_AUTH_LOGGING
#include <time.h>
#endif
#include "vpopmail.h"
#include "vauth.h"
#include "maildirquota.h"


#define MAX_BUFF 256

char Email[MAX_BUFF];
char Domain[MAX_BUFF];

int DisplayName;
int DisplayPasswd;
int DisplayClearPasswd;
int DisplayUid;
int DisplayGid;
int DisplayComment;
int DisplayDir;
int DisplayQuota;
int DisplayQuotaUsage;
int DisplayLastAuth;
int DisplayAll;

void usage();
void get_options(int argc, char **argv);
void display_user(struct vqpasswd *mypw, char *domain);
char *format_maildirquota(const char *q);

int main(int argc, char *argv[])
{
 struct vqpasswd *mypw;
 int first;
 int i;

 char User[MAX_BUFF];

    get_options(argc,argv);

    /* did we want to view an entire domain? */
    if (Domain[0] == 0 ) {
        /* didnt want to view a whole domain,
         * so try extracting Email into User and Domain
         */
        if ( (i=parse_email( Email, User, Domain, sizeof(User))) != 0 ) {
            printf("Error: %s\n", verror(i));
            vexit(i);
        }
        /* get the passwd entry for this user */
	if ( (mypw = vauth_getpw( User, Domain )) == NULL ) {
		if ( Domain[0] == 0 || strlen(Domain)==0) {
			printf("no such user %s\n", User);
		} else {
			printf("no such user %s@%s\n", User, Domain);
		}
		vexit(-1);
	}
        /* display this user's settings */
	display_user(mypw, Domain);
	vclose();
    } else {
        /* we want to see the entire domain */
	first = 1;
	while( (mypw=vauth_getall(Domain, first, 1))) {
		first = 0;
		/* display each user in the domain */
		display_user(mypw, Domain);
	}
    }
    return(vexit(0));
}

void usage()
{
	printf("vuserinfo: usage: [options] email_address\n");
	printf("options: -v (print version number)\n");
	printf("         -a (display all fields, this is the default)\n");
	printf("         -n (display name field)\n");
	printf("         -p (display crypted password)\n");
	printf("         -u (display uid field)\n");
	printf("         -g (display gid field)\n");
	printf("         -c (display comment field)\n");
	printf("         -d (display directory)\n");
	printf("         -q (display quota field)\n");
	printf("         -Q (display quota usage)\n");
#ifdef CLEAR_PASS
	printf("         -C (display clear text password)\n");
#endif
#ifdef ENABLE_AUTH_LOGGING
	printf("         -l (display last authentication time)\n");
#endif
	printf("         -D domainname (show all users on this domain)\n");
}

void get_options(int argc, char **argv)
{
 int c;
 int errflag;
 extern char *optarg;
 extern int optind;

	DisplayName = 0;
	DisplayPasswd = 0;
	DisplayUid = 0;
	DisplayGid = 0;
	DisplayComment = 0;
	DisplayDir = 0;
	DisplayQuota = 0;
	DisplayQuotaUsage = 0;
	DisplayLastAuth = 0;
	DisplayAll = 1;

	memset(Email, 0, sizeof(Email));
	memset(Domain, 0, sizeof(Domain));

	errflag = 0;
    while( !errflag && (c=getopt(argc,argv,"anpugcdqQvlD:C")) != -1 ) {
		switch(c) {
			case 'D':
				snprintf(Domain, sizeof(Domain), "%s", optarg);
				break;
			case 'v':
				printf("version: %s\n", VERSION);
				break;
			case 'n':
				DisplayName = 1;	
				DisplayAll = 0;
				break;
			case 'p':
				DisplayPasswd = 1;	
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
			case 'c':
				DisplayComment = 1;	
				DisplayAll = 0;
				break;
			case 'C':
				DisplayClearPasswd = 1;	
				DisplayAll = 0;
				break;
			case 'd':
				DisplayDir = 1;	
				DisplayAll = 0;
				break;
			case 'q':
				DisplayQuota = 1;	
				DisplayAll = 0;
				break;
			case 'Q':
				DisplayQuotaUsage = 1;	
				DisplayAll = 0;
				break;
			case 'l':
				DisplayLastAuth = 1;	
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
		snprintf(Email, sizeof(Email), "%s", argv[optind]);
		++optind;
	}

	if ( Email[0]==0 && Domain[0]==0) {
		usage();
		vexit(-1);
	}

}

void display_user(struct vqpasswd *mypw, char *domain)
{
#ifdef ENABLE_AUTH_LOGGING
 time_t mytime;
 char  *authip;
#endif
 char maildir[MAX_BUFF];

    if ( DisplayAll ) {
        printf("name:   %s\n", mypw->pw_name);
        printf("passwd: %s\n", mypw->pw_passwd);
        printf("clear passwd: %s\n", mypw->pw_clear_passwd);
        printf("uid:    %lu\n", (long unsigned)mypw->pw_uid);
        printf("gid:    %lu\n", (long unsigned)mypw->pw_gid);
        printf("gecos: %s\n", mypw->pw_gecos);

	if ( mypw->pw_gid == 0 )  
            printf("        all services available\n");
	if ( mypw->pw_gid & NO_PASSWD_CHNG ) 
            printf("        password can not be changed by user\n");
	if ( mypw->pw_gid & NO_POP ) 
            printf("        pop access closed\n");
	if ( mypw->pw_gid & NO_WEBMAIL ) 
            printf("        webmail access closed\n");
	if ( mypw->pw_gid & NO_IMAP ) 
            printf("        imap access closed\n");
	if ( mypw->pw_gid & BOUNCE_MAIL ) 
            printf("        mail will be bounced back to sender\n");
	if ( mypw->pw_gid & NO_RELAY ) 
            printf("        user not allowed to relay mail\n");
	if ( mypw->pw_gid & NO_DIALUP ) 
            printf("        no dialup flag has been set\n");
	if ( mypw->pw_gid & QA_ADMIN ) 
            printf("        has qmailadmin administrator privileges\n"); 
	if ( mypw->pw_gid & V_USER0 ) 
            printf("        user flag 0 is set\n");
	if ( mypw->pw_gid & V_USER1 ) 
            printf("        user flag 1 is set\n");
	if ( mypw->pw_gid & V_USER2 ) 
            printf("        user flag 2 is set\n");
	if ( mypw->pw_gid & V_USER3 ) 
            printf("        user flag 3 is set\n");
	if ( mypw->pw_gid & NO_SMTP ) 
            printf("        smtp access is closed\n");

        printf("dir:       %s\n", mypw->pw_dir);
        printf("quota:     %s\n", mypw->pw_shell);

        snprintf(maildir, sizeof(maildir), "%s/Maildir", mypw->pw_dir);
        if((strcmp(mypw->pw_shell, "NOQUOTA"))) {
            printf("usage:     %d%%\n", 
                vmaildir_readquota(maildir, format_maildirquota(mypw->pw_shell)));
        } else {
            printf("usage:     %s\n", mypw->pw_shell);
        }

#ifdef ENABLE_AUTH_LOGGING
	mytime = vget_lastauth(mypw, domain);
        authip = vget_lastauthip(mypw,domain);
        if ( mytime == 0 || authip == 0 || 
             strcmp(authip, NULL_REMOTE_IP) == 0 ) {
          if ( mytime != 0 ) {
	    printf("account created: %s", asctime(localtime(&mytime)));
          }
	  printf("last auth: Never logged in\n"); 
        } else {
	  printf("last auth: %s", asctime(localtime(&mytime)));
          if ( authip != NULL ) {
	     printf("last auth ip: %s\n", authip);
          }
        }
     
#endif 
    } else {
        if ( DisplayName ) printf("%s\n", mypw->pw_name);
        if ( DisplayPasswd ) printf("%s\n", mypw->pw_passwd);
#ifdef CLEAR_PASS
        if ( DisplayClearPasswd ) printf("%s\n", mypw->pw_clear_passwd);
#endif
        if ( DisplayUid ) printf("%lu\n", (long unsigned)mypw->pw_uid);
        if ( DisplayGid ) { 
            printf("%lu\n", (long unsigned)mypw->pw_gid);

	    if ( mypw->pw_gid == 0 )  
	        printf("all services available\n");
	    if ( mypw->pw_gid & NO_PASSWD_CHNG ) 
	        printf("password can not be changed by user\n");
	    if ( mypw->pw_gid & NO_POP )
		    printf("pop access closed\n");
	    if ( mypw->pw_gid & NO_WEBMAIL )
		    printf("webmail access closed\n");
	    if ( mypw->pw_gid & NO_IMAP )
		    printf("imap access closed\n");
	    if ( mypw->pw_gid & BOUNCE_MAIL )
		    printf("mail will be bounced back to sender\n");
	    if ( mypw->pw_gid & NO_RELAY )
		    printf("user not allowed to relay mail\n");
	    if ( mypw->pw_gid & NO_DIALUP )
		    printf("no dialup flag has been set\n");
	    if ( mypw->pw_gid & QA_ADMIN )
		    printf("user has qmailadmin administrator privileges\n");
	    if ( mypw->pw_gid & V_USER0 )
		    printf("user flag 0 is set\n");
	    if ( mypw->pw_gid & V_USER1 )
		    printf("user flag 1 is set\n");
	    if ( mypw->pw_gid & V_USER2 )
		    printf("user flag 2 is set\n");
	    if ( mypw->pw_gid & V_USER3 )
		    printf("user flag 3 is set\n");
	    if ( mypw->pw_gid & NO_SMTP )
		    printf("no smtp flag has been set\n");
        }
        if ( DisplayComment ) printf("%s\n", mypw->pw_gecos);
        if ( DisplayDir ) printf("%s\n", mypw->pw_dir);
        if ( DisplayQuota ) printf("%s\n", mypw->pw_shell);
        if ( DisplayQuotaUsage ) {
            snprintf(maildir, sizeof(maildir), "%s/Maildir", mypw->pw_dir);
            if((strcmp(mypw->pw_shell, "NOQUOTA"))) {
                printf("%d%%\n", 
                    vmaildir_readquota(maildir, format_maildirquota(mypw->pw_shell)));
            } else {
                printf("%s\n", mypw->pw_shell);
            }
        }

#ifdef ENABLE_AUTH_LOGGING
        if ( DisplayLastAuth ) {
	    mytime = vget_lastauth(mypw, domain);
	    printf("%s\n", asctime(localtime(&mytime)));
        }
#endif 
    }
}
