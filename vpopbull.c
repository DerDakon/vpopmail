/*
 * Copyright (C) 1999,2002 Inter7 Internet Technologies, Inc.
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
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include "config.h"
#include "vpopmail.h"
#include "vauth.h"


#define MAX_BUFF 500
#define MSG_BUF_SIZE  32768
#define TOKENS ":\r\n"

static char EmailFile[MAX_BUFF];
static char CurDir[MAX_BUFF];
static char ExcludeFile[MAX_BUFF];
static char Domain[MAX_BUFF];
static char TmpBuf[MAX_BUFF];
static char MsgBuf[MSG_BUF_SIZE];

static int Verbose;
static int DoNothing;

#define COPY_IT          0
#define HARD_LINK_IT     1
#define SYMBOLIC_LINK_IT 2

static int DeliveryMethod = COPY_IT;
int EmailFileFlag = 0;
int ExcludeFileFlag = 0;

int process_domain(char *,  FILE *, FILE *);
int copy_email( FILE *, char *, char *, struct vqpasswd *);
int in_exclude_list( FILE *, char *, char *);
void get_options(int argc,char **argv);
void usage();

int main(argc,argv)
 int argc;
 char *argv[];
{
 FILE *fsi = NULL;
 FILE *fsx = NULL;
 FILE *fsassign;
 char *domain;
 char *domain_dir = NULL;
 char *tmpstr;
 static struct stat statbuf;

  memset(TmpBuf,0,MAX_BUFF);
  memset(MsgBuf,0,MSG_BUF_SIZE);


  Verbose = 0;
  DoNothing = 0;

  if ( argc == 1 ) {
    usage();
    vexit(-1);
  }

  get_options(argc,argv);

  getcwd(CurDir,MAX_BUFF);

  if ( EmailFileFlag == 1 ) {
    if ( (fsi = fopen(EmailFile, "r")) == NULL ) {
        printf("Could not open file %s\n", EmailFile);
        vexit(-1);
    } else {
        /* make sure the file size is not 0 */
        stat(EmailFile, &statbuf);
        if(statbuf.st_size == 0) {
            printf("Error: %s is empty\n", EmailFile);
            vexit(-1);
        }
    }
  } else {
    /* require -f [email_file] */
    printf("Error: email_file not specified\n");
    usage();
    vexit(-1);
  }

  if ( ExcludeFileFlag == 1 ) {
    if ( (fsx = fopen(ExcludeFile, "r")) == NULL ) {
        printf("Could not open file %s\n", ExcludeFile);
        vexit(-1);
    }
  }

  if (( EmailFile[0] != 0 || DoNothing == 1) && Domain[0] != 0 ) {

    /* Process list of domains */
    domain = strtok(Domain, " ");
    while (domain != NULL ) {
        if((vget_assign(domain, domain_dir, 156, NULL, NULL)) != NULL) {
            process_domain(domain,  fsi, fsx );
        } else {
            printf("Error: domain %s does not exist\n", domain);
        }
        domain = strtok(NULL, " ");
    }
    vexit(0);

  } else if ( (EmailFile[0] != 0 || DoNothing == 1)  && Domain[0] == 0 ) {

    /* Process ALL domains */
    snprintf(TmpBuf, MAX_BUFF, "%s/users/assign",  QMAILDIR);
    if ( (fsassign = fopen(TmpBuf, "r")) == NULL ) {
        perror("can not open assign file");
        vexit(0);
    }

    while ( fgets(TmpBuf, 500, fsassign) != NULL ) {
      if ( (tmpstr=strtok(TmpBuf, TOKENS)) == NULL ) continue;
      if ( (domain=strtok(NULL, TOKENS)) == NULL ) continue;
      if ( (tmpstr=strtok(NULL, TOKENS)) == NULL ) continue;
      if ( (tmpstr=strtok(NULL, TOKENS)) == NULL ) continue;
      if ( (domain_dir=strtok(NULL, TOKENS)) == NULL ) continue;
      chdir(domain_dir);
      process_domain(domain,  fsi, fsx );
    }
    fclose(fsassign);
  }
  return(vexit(0));

}

int process_domain(domain, fsi, fsx )
 char *domain;
 FILE *fsi;
 FILE *fsx;
{
 char filename[MAX_BUFF];
 char hostname[128];
 static struct vqpasswd *pwent;
 time_t tm;
 int pid;
 int first = 1;

	gethostname(hostname,sizeof(hostname));
	pid=getpid();
	time (&tm);
	sprintf(filename,"%lu.%lu.%s",(long unsigned)tm,
		(long unsigned)pid,hostname);

	first = 1;
	while( (pwent = vauth_getall(domain, first, 0)) != NULL )  {
		first = 0;

		if ( !in_exclude_list( fsx, domain, pwent->pw_name) ) {
			if ( Verbose == 1 ) {
				printf("%s@%s\n", pwent->pw_name, domain);
			}
			if ( DoNothing == 0 ) {
				if(copy_email( fsi, filename, domain, pwent) == 0) {
			        if ( Verbose == 1 ) {
				        printf("%s@%s\n", pwent->pw_name, domain);
			        }
                } else {
				    printf("%s@%s: ERROR COPYING TO %s\n", pwent->pw_name, 
                        domain, pwent->pw_dir);
                }
			}
		}
	}	
	return(0);
}

int copy_email( fs_file, name, domain, pwent)
 FILE *fs_file;
 char *name;
 char *domain;
 struct vqpasswd *pwent;
{
 static char tmpbuf[512];
 static char tmpbuf1[MAX_BUFF];
 FILE *fs;
 int count;
 struct stat mystatbuf;

    /* check if the directory exists and create if needed */
    if ( stat(pwent->pw_dir, &mystatbuf ) == -1 ) {
        if ( vmake_maildir(domain, pwent->pw_dir )!= VA_SUCCESS ) {
            printf("Auto re-creation of maildir failed. vpopmail (#5.9.9)\n");
            return(-1);
        }
    }

	sprintf(tmpbuf, "%s/Maildir/new/%s", pwent->pw_dir, name );
	
	if ( DeliveryMethod == COPY_IT ) {
		rewind(fs_file);
		if ( (fs = fopen(tmpbuf, "w+")) == NULL ) {
			return(-1);
		}
		fprintf(fs, "To: %s@%s\n", pwent->pw_name, domain); 
	
		while((count=fread(MsgBuf,sizeof(char),MSG_BUF_SIZE,fs_file)) 
				!= 0 ) {
			fwrite( MsgBuf, sizeof(char), count, fs );
		}
		fclose(fs);
	} else if ( DeliveryMethod == HARD_LINK_IT ) {
		sprintf(tmpbuf1, "%s/%s", CurDir, EmailFile);
		if ( link( tmpbuf1, tmpbuf) < 0 ) {
			perror("link");
		}
	} else if ( DeliveryMethod == SYMBOLIC_LINK_IT ) {
		sprintf(tmpbuf1, "%s/%s", CurDir, EmailFile);
		if ( symlink( tmpbuf1, tmpbuf) < 0 ) {
			perror("symlink");
		}
	} else {
		printf("no delivery method set\n");
	}
	return(0);
}

int in_exclude_list( FILE *fsx, char *domain, char *user )
{
 static char tmpbuf[512];
 static char emailaddr[512];
 int  i;

	if ( fsx == NULL ) {
		return(0);
	}
	rewind(fsx);

	sprintf(emailaddr, "%s@%s", user, domain);

	while (fgets(tmpbuf,512,fsx) != NULL) {
		for(i=0;tmpbuf[i]!=0;++i) if (tmpbuf[i]=='\n') tmpbuf[i]=0;
		if ( strcmp( tmpbuf, emailaddr ) == 0 ) {
			return(1);
		}	
	}
	return(0);
}

void get_options(int argc, char **argv)
{
 int n = 0;
 int c;
 int errflag;
 extern char *optarg;
 extern int optind;

    memset(Domain, 0, MAX_BUFF);
    memset(EmailFile, 0, MAX_BUFF);
    memset(ExcludeFile, 0, MAX_BUFF);

    errflag = 0;
    EmailFileFlag = 0;
    ExcludeFileFlag = 0;
    while( !errflag && (c=getopt(argc,argv,"Vvcshnf:e:")) != -1 ) {
        switch(c) {
            case 'v':
                printf("version: %s\n", VERSION);
                break;
            case 'V':
                Verbose = 1;
                break;
            case 's':
                DeliveryMethod = SYMBOLIC_LINK_IT; 
                break;
            case 'c':
                DeliveryMethod = COPY_IT; 
                break;
            case 'f':
                EmailFileFlag = 1;
                strncpy( EmailFile, optarg, MAX_BUFF-1);
                break;
            case 'e':
                ExcludeFileFlag = 1;
                strncpy( ExcludeFile, optarg, MAX_BUFF-1);
                break;
            case 'h':
                DeliveryMethod = HARD_LINK_IT; 
                break;
            case 'n':
                DoNothing = 1;
                break;
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

    n = 0;
    while ( optind < argc ) { 
        if((n=1)) strncat(Domain, " ", MAX_BUFF);
        strncat(Domain, argv[optind], MAX_BUFF);
        n = 1;
        ++optind;
    }
}

void usage()
{
	printf("usage: vpopbull [options] -f [email_file] [virtual_domain] [...]\n");
	printf("       -v (print version number)\n");
	printf("       -V (verbose)\n");
	printf("       -f email_file (file with message contents)\n");
	printf("       -e exclude_email_addr_file (list of addresses to exclude)\n");
	printf("       -n (don't mail. Use with -V to list accounts)\n");
	printf("       -c (default, copy file)\n"); 
	printf("       -h (use hard links)\n"); 
	printf("       -s (use symbolic links)\n"); 
}
