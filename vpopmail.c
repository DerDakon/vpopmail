/*
 * vpopmail library
 * part of the vpopmail package
 * 
 * Copyright (C) 2000,2001 Inter7 Internet Technologies, Inc.
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
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#ifdef HAVE_SYS_VARARGS_H
#include <sys/varargs.h>
#endif
#include <signal.h>
#include <ctype.h>
#include <fcntl.h>
#include <time.h>
#include <dirent.h>
#include <pwd.h>
#include "config.h"
#include "md5.h"
#include "vpopmail.h"
#include "file_lock.h"
#include "vauth.h"

#define MAX_BUFF 500
static char Crypted[MAX_BUFF];
static char TmpBuf[MAX_BUFF];
static char TmpBuf1[MAX_BUFF];
static char TmpBuf2[MAX_BUFF];

#define FILE_SIZE 156
static char DomainSubDir[FILE_SIZE];

#define BUFF_SIZE 300

#ifdef POP_AUTH_OPEN_RELAY
int fdm;
static char relay_template[300];
static char *binqqargs[4];
char bin0[BUFF_SIZE];
char bin1[BUFF_SIZE];
char bin2[BUFF_SIZE];
#endif

int verrori = 0;

extern int cdb_seek();

/* Global Flags */
int NoMakeIndex = 0;
int OptimizeAddDomain = 0;

#define TOKENS " \t"
#define CDB_TOKENS ":\n\r"


#ifdef IP_ALIAS_DOMAINS
int host_in_locals(char *domain);
#endif

static char gen_chars[] = "abcdefghijklmnopqrstuvwxyz" \
                          "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
                          "0123456789.@!#%*";


/* 
 * Add a domain to the entire email system
 *
 * input: domain name
 *        directory to put the files
 *        uid and gid to assign to the files
 */
int vadddomain( char *domain, char *dir, uid_t uid, gid_t gid )
{
 FILE *fs;
 int i;
 char *domain_sub_dir;
 char tmpbuf[156];

    /* we only do lower case */
    lowerit(domain);
    if ( strlen( domain ) > MAX_PW_DOMAIN ) return(VA_DOMAIN_NAME_TOO_LONG);

    /* check invalid email domain characters */
    for(i=0;domain[i]!=0;++i) {
        if (i == 0 && domain[i] == '-' ) return(VA_INVALID_DOMAIN_NAME);
        if (isalnum((int)domain[i])==0 && domain[i]!='-' && domain[i]!='.')
            return(VA_INVALID_DOMAIN_NAME);

    }
    if ( domain[i-1] == '-' ) return(VA_INVALID_DOMAIN_NAME);

    /* after the name is okay, check if it already exists */
    if ( vget_assign(domain, NULL, 156, NULL, NULL ) != NULL ) {
        chdir(TmpBuf1);
        return(VA_DOMAIN_ALREADY_EXISTS);
    }

    /* set our file creation mask for machines where the
     * sysadmin has tightened default permissions
     */
    umask(VPOPMAIL_UMASK);

    /* remember where we are */
    getcwd(TmpBuf1, MAX_BUFF);


    /* go to the directory
     * check for error and return error on error
     */
    if ( chdir(dir) != 0 ) {
	return(VA_BAD_V_DIR);
    }

    /* go into our vpopmail domains directory */
    if ( chdir(DOMAINS_DIR) != 0 ) {

	/* if it's not there, no problem, just try to create it */
        if ( mkdir(DOMAINS_DIR, VPOPMAIL_DIR_MODE) != 0 ) {
            if ( chdir(TmpBuf1) != 0 ) {
            	return(VA_CAN_NOT_MAKE_DOMAINS_DIR);
	    } 
        }

	/*  set the permisions on our new directory */
    	chown(DOMAINS_DIR,uid,gid);

	/* try this again */
	if ( chdir(DOMAINS_DIR) != 0 ) {
            return(VA_CAN_NOT_MAKE_DOMAINS_DIR);
	}
    }

    /* since domains can be added under any /etc/passwd
     * user, we have to create dir_control information
     * for each user/domain combination
     */
    snprintf(tmpbuf, 156, "dom_%lu", (long unsigned)uid);

    open_big_dir(tmpbuf, uid, gid);
    domain_sub_dir = next_big_dir(uid, gid);
    close_big_dir(tmpbuf, uid, gid);

    if ( strlen(domain_sub_dir) > 0 ) {
	snprintf(DomainSubDir, FILE_SIZE, "%s/%s", domain_sub_dir, domain);
    } else {
	snprintf(DomainSubDir, FILE_SIZE, "%s", domain);
    }
   
    if ( r_mkdir(DomainSubDir, uid, gid ) != 0 ) {
        chdir(TmpBuf1);
        return(VA_COULD_NOT_MAKE_DOMAIN_DIR);
    }
    
    if ( chdir(DomainSubDir) != 0 ) {
        chdir(TmpBuf1);
        return(VA_BAD_D_DIR);
    }

    snprintf(TmpBuf, MAX_BUFF, 
        "%s/%s/%s/.qmail-default", dir, DOMAINS_DIR, DomainSubDir);
    if ( (fs = fopen(TmpBuf, "w+"))==NULL) {
        chdir(TmpBuf1);
        return(VA_COULD_NOT_OPEN_QMAIL_DEFAULT);
    } else {
        fprintf(fs, "| %s/bin/vdelivermail '' bounce-no-mailbox\n",
             VPOPMAILDIR);
        fclose(fs);
    }
    snprintf(TmpBuf, MAX_BUFF, "%s/%s/%s", dir, DOMAINS_DIR, DomainSubDir);

    add_domain_assign( domain, domain, TmpBuf, uid, gid );

    /* recursively change ownership to new file system entries */
    snprintf(TmpBuf, MAX_BUFF, "%s/%s/%s", dir, DOMAINS_DIR, DomainSubDir);
    r_chown(TmpBuf, uid, gid);

    /* ask the authentication module to add the domain entry */
    vauth_adddomain( domain );

    /* ask qmail to re-read it's new control files */
    if ( OptimizeAddDomain == 0 ) {
        signal_process("qmail-send", SIGHUP);
    }

    /* return back to the callers directory and return success */
    chdir(TmpBuf1);

    return(VA_SUCCESS);
}

int vdeldomain( char *domain )
{
 struct stat statbuf;
 char Dir[156];
 char real_domain[156];
 char *tmpstr;
 uid_t uid;
 gid_t gid;

    getcwd(TmpBuf1, MAX_BUFF);

    lowerit(domain);
    strcpy(real_domain, domain);
    tmpstr = vget_assign(domain, Dir, 156, &uid, &gid );
    if ( tmpstr == NULL ) {
	return(VA_DOMAIN_DOES_NOT_EXIST);
    }

    /* if this is an NOT aliased domain */
    if ( strcmp(real_domain, domain) == 0 ) {
        if ( stat(Dir, &statbuf) != 0 ) {
            chdir(TmpBuf1);
            return(VA_DOMAIN_DOES_NOT_EXIST);
        }

        /* if it's a symbolic link just remove the link */
        if ( S_ISLNK(statbuf.st_mode) ) {
           unlink(Dir);
        } else {
	    /* delete the domain from the filesystem */ 
            if ( vdelfiles(Dir) != 0 ) {
              printf("could not delete directory %s\n", domain);
              return(VA_BAD_DIR);
	    }
            /* call the auth module to delete the domain from the storage */
            vauth_deldomain(domain);
        }
    }

    /* delete the assign file line */
    del_domain_assign(real_domain, domain, Dir, uid, gid);

    /* delete the email domain from the qmail control files */
    del_control(real_domain);

    /* delete the dir control info for this domain */
    vdel_dir_control(real_domain);

    /* decrement the master domain control info */
    snprintf(Dir, 156, "dom_%lu", (long unsigned)uid);
    dec_dir_control(Dir, uid, gid);

    /* send a HUP signal to qmail-send process to reread control files */
    signal_process("qmail-send", SIGHUP);

    /* return back to the callers directory */
    chdir(TmpBuf1);

    return(VA_SUCCESS);

}

/*
 * Add a virtual domain user
 */
int vadduser( char *username, char *domain, char *password, char *gecos, 
              int apop )
{
 char Dir[156];
 char *dir;
 uid_t uid = VPOPMAILUID;
 gid_t gid = VPOPMAILGID;

    /* check gecos for : characters - bad */
    if ( strchr(gecos,':')!=0) return(VA_BAD_CHAR);

    if ( strlen(username) > MAX_PW_NAME ) return(VA_USER_NAME_TOO_LONG);
    if ( strlen(username) == 1 ) return(VA_ILLEGAL_USERNAME);
    if ( strlen(domain) > MAX_PW_DOMAIN ) return(VA_DOMAIN_NAME_TOO_LONG);
    if ( strlen(password) > MAX_PW_CLEAR_PASSWD ) return(VA_PASSWD_TOO_LONG);
    if ( strlen(gecos) > MAX_PW_GECOS )    return(VA_GECOS_TOO_LONG);

    umask(VPOPMAIL_UMASK);
    lowerit(username);
    lowerit(domain);

    if ( is_username_valid(username) != 0 ) return(VA_ILLEGAL_USERNAME);
    if ( is_domain_valid(domain) != 0 ) return(VA_INVALID_DOMAIN_NAME);

    if ( vauth_getpw( username, domain ) != NULL ) {
        return(VA_USERNAME_EXISTS);
    }

    getcwd(TmpBuf1, MAX_BUFF);
    if ( domain==0 || domain[0] == 0 ) {
    	if ( chdir(VPOPMAILDIR) != 0 ) {
        	chdir(TmpBuf1);
        	return(VA_BAD_DIR);
    	}
        if ( chdir("users") != 0 ) {
            chdir(TmpBuf1);
            return(VA_BAD_U_DIR);
        }
    } else {
	if ( vget_assign(domain, Dir, 156, &uid, &gid)==NULL){
	    return(VA_DOMAIN_DOES_NOT_EXIST);
	}

        if ( chdir(Dir) != 0 ) {
            chdir(TmpBuf1);
            return(VA_BAD_D_DIR);
        }
    }

    if ( (dir=make_user_dir(username, domain, uid, gid)) == NULL ) {
        if (verrori != 0 ) return(verrori);
        else return(VA_BAD_U_DIR);
    }
        
    if ( apop & USE_APOP ) {
        if (vauth_adduser(username, domain, password, gecos, dir, apop )!=0){
		return(VA_BAD_U_DIR);
	}
    } else {
        if (vauth_adduser(username, domain, password, gecos, dir, apop )!=0){
		return(VA_BAD_U_DIR);
	}
    }
    if ( domain == NULL || domain[0] == 0 ) {
        add_user_assign(username, dir );
    }
#ifdef SQWEBMAIL_PASS
    {
       struct vqpasswd *mypw;
        mypw = vauth_getpw( username, domain);
        if ( mypw != NULL ) {
		vsqwebmail_pass( mypw->pw_dir, mypw->pw_passwd, uid, gid);
	}
    }
#endif

#ifdef ENABLE_AUTH_LOGGING
    vset_lastauth(username,domain,NULL_REMOTE_IP);
#endif

    chdir(TmpBuf1);
    return(VA_SUCCESS);
}

char randltr(void)
{
 char rand;
 char retval = 'a';

    rand = random() % 64;

    if (rand < 26) retval = rand + 'a';
    if (rand > 25) retval = rand - 26 + 'A';
    if (rand > 51) retval = rand - 52 + '0';
    if (rand == 62) retval = ';';
    if (rand == 63) retval = '.';
    return retval;
}

/*
 * encrypt a password 
 * Input
 * clearpass = pointer to clear text password
 * ssize     = size of the crypted pointer buffer
 * 
 * Output
 *  copies the encrypted password into the crypted 
 *      character pointer
 * 
 * Return code:
 *   VA_CRYPT_FAILED = encryption failed
 *   VA_SUCCESS = 0  = encryption success
 * 
 */
int mkpasswd3( char *clearpass, char *crypted, int ssize )
{
 char *tmpstr;
 char salt[9];
 time_t tm;

    time(&tm);
    srandom (tm % 65536);

#ifdef MD5_PASSWORDS
    salt[0] = '$';
    salt[1] = '1';
    salt[2] = '$';
    salt[3] = randltr();
    salt[4] = randltr();
    salt[5] = randltr();
    salt[6] = randltr();
    salt[7] = randltr();
    salt[8] = 0;
#else
    salt[0] = randltr();
    salt[1] = randltr();
    salt[2] = 0;
#endif

    tmpstr = crypt(clearpass,salt);
    if ( tmpstr == NULL ) {
        return(VA_CRYPT_FAILED);
    }
    strncpy(crypted,tmpstr, ssize);
    return(VA_SUCCESS);
}

/* 
 * prompt the command line and get a password twice, that matches 
 */
char *vgetpasswd( user ) 
 char *user;
{
 static char pass1[128];
 static char pass2[128];
 static char tmpstr[128];

    memset(pass1, 0, 128);
    memset(pass2, 0, 128);
    snprintf( tmpstr, 128, "Please enter password for %s: ", user);

    while( 1 ) {
        strncpy( pass1, getpass(tmpstr), 128);
        strncpy( pass2, getpass("enter password again: "), 128);
        if ( strcmp( pass1, pass2 ) != 0 ) {
            printf("Passwords do not match, try again\n");
        } else {
            break;
        }
    }
    return(pass1);
}

/* 
 * vdelfiles : delete a directory tree
 *
 * input: directory to start the deletion
 * output: 
 *         0 on success
 *        -1 on failer
 */
int vdelfiles(dir)
 char *dir;
{
 DIR *mydir;
 struct dirent *mydirent;
 struct stat statbuf;

    /* Modified By David Wartell david@actionwebservices.com to work with 
     * Solaris. Unlike Linux, Solaris will NOT return error when unlink() 
     * is called on a directory.   A correct implementation to support 
     * Linux & Solaris is to test to see if the file is a directory.  
     * If it is not a directory unlink() it. 
     * If unlink() returns an error return error.
     */

    if (lstat(dir, &statbuf) == 0) {

        /* if dir is not a directory unlink it */
        if ( !( S_ISDIR(statbuf.st_mode) ) ) {

            if ( unlink(dir) == 0 ) {
                /* return success we deleted the file */
                return(0);
            } else {
                /* error, return error to calling function, 
                 * we couldn't unlink the file 
                 */
                return(-1);
            }
        }

    } else {
        /* error, return error to calling function, 
         * we couldn't lstat the file 
         */
        return(-1);
    }

	/* go to the directory, and check for error */ 
    if (chdir(dir) == -1) {
		/* error, return error to calling function */
		return(-1);
	}

	/* open the directory and check for an error */
    if ( (mydir = opendir(".")) == NULL ) {

		/* error, return error */
		printf("Failed to opendir()");
		return(-1);
	}

    while((mydirent=readdir(mydir))!=NULL){

		/* skip the current directory and the parent directory entries */
        if ( strncmp(mydirent->d_name,".", 2) !=0 &&
             strncmp(mydirent->d_name,"..", 3)!=0 ) {

			/* stat the file to check it's type, I/O expensive */
            stat( mydirent->d_name, &statbuf);

			/* Is the entry a directory? */
            if ( S_ISDIR(statbuf.st_mode) ) {

				/* delete the sub tree, -1 means an error */
                if ( vdelfiles ( mydirent->d_name) == -1 ) {

					/* on error, close the directory stream */
    				closedir(mydir);

					/* and return error */
					return(-1);
				}

			/* the entry is not a directory, unlink it to delete */
            } else {

				/* unlink the file and check for error */
                if (unlink(mydirent->d_name) == -1) {

					/* print error message and return and error */
                    printf ("Failed to delete directory %s", mydirent->d_name);
                    return(-1);
                }
            }
        }
    }
	
	/* close the directory stream, we don't need it anymore */
    closedir(mydir);

	/* go back to the parent directory and check for error */
    if (chdir("..") == -1) {

		/* print error message and return an error */
		printf("Failed to cd to parent");
		return(-1);
	}

	/* delete the directory, I/O expensive */
    rmdir(dir);

	/* return success */
    return(0);
}

/* 
 * Add a domain to all the control files 
 * And signal qmail
 * domain is the domain name
 * dir is the full path to the domain directory
 * uid and gid are the uid/gid to store in the assign file
 */
int add_domain_assign( char *alias_domain, char *real_domain,
                       char *dir, uid_t uid, gid_t gid )
{
 FILE *fs1 = NULL;
 struct stat mystat;
 static char tmpstr1[MAX_BUFF];
 static char tmpstr2[MAX_BUFF];
 static char tmpstr3[MAX_BUFF];

    snprintf(tmpstr1, MAX_BUFF, "%s/users/assign", QMAILDIR);

    /* stat assign file, if it's not there create one */
    if ( stat(tmpstr1,&mystat) != 0 ) {
        /* put a . on one line by itself */
        if ( (fs1 = fopen(tmpstr1, "w+"))==NULL ) {
            printf("could not open assign file\n");
            return(-1);
        }
        fputs(".\n", fs1);
        fclose(fs1);
    }

    snprintf(tmpstr3, MAX_BUFF, "+%s-:%s:%lu:%lu:%s:-::",
        alias_domain, real_domain, (long unsigned)uid, (long unsigned)gid, dir);

    /* update the file and add the above line and remove duplicates */
    update_file(tmpstr1, tmpstr3);

    /* set the mode in case we are running with a strange mask */
    chmod(tmpstr1, VPOPMAIL_QMAIL_MODE ); 

    /* compile the assign file */
    if ( OptimizeAddDomain == 0 ) {
        update_newu();
    }

    /* If we have more than 50 domains in rcpthosts
     * make a morercpthosts and compile it
     */
    if ( count_rcpthosts() >= 50 ) {
        snprintf(tmpstr1, MAX_BUFF, "%s/control/morercpthosts", QMAILDIR);
        update_file(tmpstr1, alias_domain);
        snprintf(tmpstr1, MAX_BUFF, "%s/control/morercpthosts", QMAILDIR);
        chmod(tmpstr1, VPOPMAIL_QMAIL_MODE ); 
        if ( OptimizeAddDomain == 0 ) {
            compile_morercpthosts();
        }

    /* or just add to rcpthosts */
    } else {
        snprintf(tmpstr1, MAX_BUFF, "%s/control/rcpthosts", QMAILDIR);
        update_file(tmpstr1, alias_domain);
        snprintf(tmpstr1, MAX_BUFF, "%s/control/rcpthosts", QMAILDIR);
        chmod(tmpstr1, VPOPMAIL_QMAIL_MODE ); 
    }
    
    /* Add to virtualdomains file and remove duplicates  and set mode */
    snprintf(tmpstr1, MAX_BUFF, "%s/control/virtualdomains", QMAILDIR );
    snprintf(tmpstr2, MAX_BUFF, "%s:%s", alias_domain, alias_domain );
    update_file(tmpstr1, tmpstr2);
    chmod(tmpstr1, VPOPMAIL_QMAIL_MODE ); 

    /* make sure it's not in locals and set mode */
    snprintf(tmpstr1, MAX_BUFF, "%s/control/locals", QMAILDIR);
    remove_line( alias_domain, tmpstr1); 
    chmod(tmpstr1, VPOPMAIL_QMAIL_MODE ); 

    return(0);
}

/*
 * delete a domain from the control files
 */
int del_control( domain ) 
 char *domain;
{
 static char tmpbuf1[MAX_BUFF];
 static char tmpbuf2[MAX_BUFF];

    snprintf(tmpbuf1, MAX_BUFF, "%s/control/rcpthosts", QMAILDIR);
    if ( remove_line( domain, tmpbuf1) == 0 ) {
        snprintf(tmpbuf1, MAX_BUFF, "%s/control/morercpthosts", QMAILDIR);
        if ( remove_line( domain, tmpbuf1) == 1 ) {
            struct stat statbuf;
            if ( stat( tmpbuf1, &statbuf) == 0 ) {
                if ( statbuf.st_size == 0 ) {
                    unlink(tmpbuf1);
                    strncat(tmpbuf1, ".cdb", MAX_BUFF);
                    unlink(tmpbuf1);
                } else {
                    compile_morercpthosts();
                    chmod(tmpbuf1, VPOPMAIL_QMAIL_MODE ); 
                }
            }
        }
    } else {
        chmod(tmpbuf1, VPOPMAIL_QMAIL_MODE ); 
    }

    snprintf(tmpbuf1, MAX_BUFF, "%s:%s", domain, domain);
    snprintf(tmpbuf2, MAX_BUFF, "%s/control/virtualdomains", QMAILDIR);
    remove_line( tmpbuf1, tmpbuf2); 
    chmod(tmpbuf2, VPOPMAIL_QMAIL_MODE ); 

    return(0);
}

/*
 * delete a domain from the usrs/assign file
 * input : lots ;)
 * output : 0 = success
 *          less than error = failure
 *
 */
int del_domain_assign( char *alias_domain, char *real_domain, 
                       char *dir, gid_t uid, gid_t gid )  
{
 int len1, len2;
 char *tmpstr1, *tmpstr2;

	/* get some memory for string1 */
	len1 = (strlen(alias_domain)) + strlen(real_domain) + strlen(dir) + 40;
	if ( (tmpstr1 = calloc(1, len1)) == NULL ) {
		return(-1);
	}

	/* get some memory for string2 */
	len2 = strlen(QMAILDIR) + 30; 
	if ( (tmpstr2 = calloc(1, len2)) == NULL ) {
		free(tmpstr1);
		return(-1);
	}

    /* format the removal string */ 
    snprintf(tmpstr1, MAX_BUFF, "+%s-:%s:%lu:%lu:%s:-::", alias_domain, 
        real_domain, (long unsigned)uid, (long unsigned)gid, dir);

    /* format the file name */
    snprintf(tmpstr2, MAX_BUFF, "%s/users/assign", QMAILDIR);

    /* remove the formatted string from the file */
    remove_line( tmpstr1, tmpstr2); 

    /* force the permission on the file */
    chmod(tmpstr2, VPOPMAIL_QMAIL_MODE ); 

    /* free the temporary memory */
    free(tmpstr1);
    free(tmpstr2);

    /* compile assign file */
    update_newu();

    return(0);
}

/*
 * Generic remove a line from a file utility
 * input: template to search for
 *        file to search inside
 *
 * output: less than zero on failure
 *         0 if successful
 *         1 if match found
 */
int remove_line( char *template, char *filename )
{
 int len;
 char *tmpbuf;
 struct stat statbuf;
 FILE *fs1;
 FILE *fs2;
#ifdef FILE_LOCKING
 FILE *fs3;
#endif
 int found;
 int i;

	/* if we can't stat the file, return error */
    if ( stat(filename,&statbuf) == -1 ) {
		return(-1);
	}

	len = strlen(filename) + 10;
	if ( len < 300 ) len = 300; 
	if ( (tmpbuf = calloc(1, len)) == NULL ) {
		printf("%d bytes of memory not available\n", len);
		return(-1);
	}

#ifdef FILE_LOCKING
	/* format the file name */
    strncpy(tmpbuf, filename, len);
    strncat(tmpbuf, ".lock", len);


	/* open the file with write permissions
	 * and check for error 
	 */
	if ( (fs3 = fopen(tmpbuf, "w+")) == NULL ) {
		/* return error */
		printf("could not open lock file %s\n", tmpbuf);
		free(tmpbuf);
		return(-1);
	}

	/* ask for a write lock on the file
	 * we don't want anyone writing to it now 
	 */
	if ( get_write_lock(fs3) < 0 ) {

		/* remove lock */
		unlock_lock(fileno(fs3), 0, SEEK_SET, 0);
		fclose(fs3);

		/* release the memory */
		free(tmpbuf);

		/* print error message */
		printf("could not get write lock on %s\n", tmpbuf);

		/* return error */
		return(-1);
	}
#endif

	/* format a new string */
    strncpy(tmpbuf, filename, len);
    strncat(tmpbuf, ".bak", len);

	/* remove the file */
    unlink(tmpbuf);

	/* move the orignal file to the .bak file */
    rename(filename, tmpbuf);

	/* open the file
	 * and check for error
	 */
    if ( (fs1 = fopen(filename, "w+")) == NULL ) {

#ifdef FILE_LOCKING
		/* release resources */
		fclose(fs3);
#endif
		free(tmpbuf);

		printf("%s file would not open w+\n", filename);
		return(-1);
	}

	/* open in read mode 
	 * and check for error 
	 */
    if ( (fs2 = fopen(tmpbuf, "r+")) == NULL ) {
		if ( (fs2 = fopen(tmpbuf, "w+")) == NULL ) {
			printf("%s would not open r+ or w+\n", tmpbuf);
			fclose(fs1);
#ifdef FILE_LOCKING
			unlock_lock(fileno(fs3), 0, SEEK_SET, 0);
			fclose(fs3);
#endif
			free(tmpbuf);
			return(-1);
		}
	}

	/* pound away on the files 
	 * run the search algorythm
	 */
    found = 0;
    while (fgets(tmpbuf,len,fs2)!=NULL){
        for(i=0;tmpbuf[i]!=0;++i) if (tmpbuf[i]=='\n') tmpbuf[i]=0;
        if ( strcmp(template, tmpbuf) != 0) {
            fputs(tmpbuf, fs1);
            fputs("\n", fs1);
        } else {
            found = 1;
        }
    }

	/* we are done with these two, release the resources */
    fclose(fs1);
    fclose(fs2);

	/* format more strings */
    strncpy(tmpbuf, filename, len);
    strncat(tmpbuf, ".bak", len);

	/* remove the .bak file */
    unlink(tmpbuf);

	/* release the formatting string temporary memory, not needed anymore */
	free(tmpbuf);

#ifdef FILE_LOCKING
	/* unlock, we are done */
	unlock_lock(fileno(fs3), 0, SEEK_SET, 0);

	/* close the lock file to release resources */
	fclose(fs3);
#endif

	/* return 0 = everything went okay, but we didn't find it
	 *        1 = everything went okay and we found a match
	 */
    return(found);

}

/* 
 * Recursive change ownership utility 
 */
int r_chown( path, owner, group )
 char *path;
 uid_t owner;
 gid_t group;
{
 DIR *mydir;
 struct dirent *mydirent;
 struct stat statbuf;

    chown(path,owner,group);
    if (chdir(path) == -1) {
        printf("Failed to cd to directory %s", path);
        return(-1);
    }
    mydir = opendir(".");
    if ( mydir == NULL ) { 
        printf("Failed to opendir()");
        return(-1);
    }

    while((mydirent=readdir(mydir))!=NULL){
        if ( strncmp(mydirent->d_name,".", 2)!=0 &&
             strncmp(mydirent->d_name,"..", 3)!=0 ) {
            stat( mydirent->d_name, &statbuf);
            if ( S_ISDIR(statbuf.st_mode) ) {
                r_chown( mydirent->d_name, owner, group);
            } else {
                chown(mydirent->d_name,owner,group);
            }
        }
    }
    if (chdir("..") == -1) {printf("Failed to cd to parent");return(-1);}
    closedir(mydir);
    return(0);
}

/* 
 * Send a signal to a process utility function
 *
 * name    = name of process
 * sig_num = signal number 
 */
int signal_process( name, sig_num)
 char *name;
 int  sig_num; 
{
 FILE *ps;
 char *tmpstr;
 int  col;
 pid_t tmppid;
 pid_t mypid;
 int  pid_col=0;
 static char pid[MAX_BUFF];

    mypid = getpid();
    memset(pid,0,MAX_BUFF);
    if ( (ps = popen(PS_COMMAND, "r")) == NULL ) {
        perror("popen on ps command");
        return(-1);
    }

    if (fgets(TmpBuf, MAX_BUFF, ps)!= NULL ) {
        col=0;
        tmpstr = strtok(TmpBuf, TOKENS);
        while (tmpstr != NULL ) {
            if (strcmp(tmpstr, "PID") == 0 ) {
                pid_col = col;
            }
            tmpstr = strtok(NULL, TOKENS);
            ++col;
        }
    }

    while (fgets(TmpBuf, MAX_BUFF, ps)!= NULL ) {
        if ( strstr( TmpBuf, name ) != NULL && 
             strstr(TmpBuf,"supervise")==NULL) {
            tmpstr = strtok(TmpBuf, TOKENS);
            col = 0;
            do {
                if( col == pid_col ) {
                    strncpy(pid, tmpstr, MAX_BUFF);
                    break;
                } 
                ++col;
                tmpstr = strtok(NULL, TOKENS);
            } while ( tmpstr!=NULL );
    	    tmppid = atoi(pid);
            if ( tmppid != mypid ) { 
	      kill(tmppid,sig_num);
            }
        }
    }
    pclose(ps);
    return(0);
}

/*
 * Compile the users/assign file using qmail-newu program
 */
int update_newu()
{
 int pid;

    pid=vfork();
    if ( pid==0){
        execl(QMAILNEWU,"qmail-newu", NULL);
        exit(127);
    } else {
        wait(&pid);
    }
    return(0);
}

/*
 * parse out user and domain from an email address utility function
 * 
 * email  = input email address
 * user   = parsed user
 * domain = parsed domain
 * 
 * return 0 on success
 *       -1 on error
 */
int parse_email( email, user, domain, buff_size ) 
 char *email;
 char *user;
 char *domain;
 int  buff_size;
{
 int i;
 int j;
 int k;
 int found;

    for( i=0,j=0,found=0; found==0 && j<buff_size && email[i]!=0; ++i,++j) {
        for(k=0;ATCHARS[k]!=0;++k){
            if ( email[i] == ATCHARS[k] ) {
                found = 1;
                continue;
            }
        }
        if ( found == 0 )  { 
          user[j] = email[i];
        }
    }
    user[j] = 0;
    lowerit(user);

    domain[0] = 0;
    if (email[i]!=0) {
        for(j=0;j<buff_size&&email[i]!=0&&email[i]!='@';++i,++j) {
            domain[j] = email[i];
        }
        domain[j] = 0;
        lowerit(domain);
    }

    if ( is_username_valid( user ) != 0 ) {
       printf("user invalid %s\n", user);
       return(-1);
    }

    if ( is_domain_valid( domain ) != 0 ) {
       printf("domain invalid %s\n", domain);
       return(-1);
    }

    /* if the domain is blank put in the default domain 
     * if it was configured with --enable-default-domain=something
     */
    vset_default_domain(domain);

    vget_real_domain(domain, buff_size);

    return(0);
} 

/*
 * update a users virtual password file entry with a different password
 */
int vpasswd( char *username, char *domain, char *password, int apop )
{
 struct vqpasswd *mypw;
#ifdef SQWEBMAIL_PASS
 uid_t uid;
 gid_t gid;
#endif

    if ( strlen(username) > MAX_PW_NAME ) return(VA_USER_NAME_TOO_LONG);
    if ( strlen(username) == 1 ) return(VA_ILLEGAL_USERNAME);
    if ( strlen(domain) > MAX_PW_DOMAIN ) return(VA_DOMAIN_NAME_TOO_LONG);
    if ( strlen(password) > MAX_PW_CLEAR_PASSWD ) return(VA_PASSWD_TOO_LONG);

    lowerit(username);
    lowerit(domain);

    mypw = vauth_getpw( username, domain);
    if ( mypw == NULL ) return(-1); 

    if ( mypw->pw_gid & NO_PASSWD_CHNG ) return(-1);
    mkpasswd3(password,Crypted, MAX_BUFF);
    mypw->pw_passwd = Crypted;

#ifdef CLEAR_PASS
    mypw->pw_clear_passwd = password;
#endif
#ifdef SQWEBMAIL_PASS
    vget_assign(domain, NULL, 0, &uid, &gid );
    vsqwebmail_pass( mypw->pw_dir, Crypted, uid, gid);
#endif
    return (vauth_setpw( mypw, domain));
}

/* 
 * add a local user to the users/assign file and compile it
 */
int add_user_assign( char *user, char *dir )
{
 FILE *fs = NULL;
 struct stat mystat;
 static char tmpstr1[MAX_BUFF];
 static char tmpstr2[MAX_BUFF];
 int new_file = 0;

    /* stat assign file, if it's not there create one */
    snprintf(tmpstr1, MAX_BUFF, "%s/users/assign", QMAILDIR);
    if ( stat(tmpstr1,&mystat) != 0 ) new_file = 1;

    snprintf(tmpstr1, MAX_BUFF, "%s/users/assign", QMAILDIR);
    if ( dir == 0 || dir[0] == 0 ) {
        snprintf(tmpstr2, MAX_BUFF, "=%s:%s:%lu:%lu:%s/users/%s:::",
            user, user, (long unsigned)VPOPMAILUID, 
            (long unsigned)VPOPMAILGID, VPOPMAILDIR, user);
    } else {
        snprintf(tmpstr2, MAX_BUFF, "=%s:%s:%lu:%lu:%s/users/%s/%s:::",
            user, user, (long unsigned)VPOPMAILUID, 
            (long unsigned)VPOPMAILGID, VPOPMAILDIR, dir, user);
    }
    update_file(tmpstr1, tmpstr2);

    snprintf(tmpstr1, MAX_BUFF, "%s/users/assign", QMAILDIR);
    if ( dir == 0 || dir[0] == 0 ) {
        snprintf(tmpstr2, MAX_BUFF, "+%s-:%s:%lu:%lu:%s/users/%s:-::",
            user, user, (long unsigned)VPOPMAILUID, 
            (long unsigned)VPOPMAILGID, VPOPMAILDIR, user);
    } else {
        snprintf(tmpstr2, MAX_BUFF, "+%s-:%s:%lu:%lu:%s/users/%s/%s:-::",
            user, user, (long unsigned)VPOPMAILUID, 
            (long unsigned)VPOPMAILGID, VPOPMAILDIR, dir, user);
    }
    update_file(tmpstr1, tmpstr2);

    if ( new_file == 1 ) {
        snprintf(tmpstr1, MAX_BUFF, "%s/users/assign", QMAILDIR);
        fs = fopen(tmpstr1, "w+");
        fprintf(fs, ".\n");
        fclose(fs);
    }
    update_newu();
    return(0);
}

/*
 * remove a local user from the users/assign file and recompile
 */
int del_user_assign( char *user ) 
{
 static char tmpbuf1[MAX_BUFF];
 static char tmpbuf2[MAX_BUFF];
 struct vqpasswd *mypw;

    
    tmpbuf1[0] = 0;
    if ( (mypw = vauth_getpw( user, tmpbuf1 )) == NULL ) {
        return(-1);
    }
    snprintf(tmpbuf2, MAX_BUFF, "%s/users/assign", QMAILDIR);

    snprintf(tmpbuf1, MAX_BUFF, "=%s:%s:%lu:%lu:%s:::",
        user, user, (long unsigned)VPOPMAILUID, 
        (long unsigned)VPOPMAILGID, mypw->pw_dir);
    remove_line( tmpbuf1, tmpbuf2); 

    snprintf(tmpbuf1, MAX_BUFF, "+%s-:%s:%lu:%lu:%s:-::",
        user, user, (long unsigned)VPOPMAILUID, 
        (long unsigned)VPOPMAILGID, mypw->pw_dir);
    remove_line( tmpbuf1, tmpbuf2); 

    update_newu();

    return(0);
}

/*
 * delete a user from a virtual domain password file
 */
int vdeluser( char *user, char *domain )
{
 struct vqpasswd *passent;
 char *tmpstr;
 char Dir[156];
 uid_t uid;
 gid_t gid;

    if ( user == 0 || strlen(user)<=0) { 
	return(VA_ILLEGAL_USERNAME);
    }

    umask(VPOPMAIL_UMASK);
    lowerit(user);
    lowerit(domain);
    if ((passent = vauth_getpw(user, domain)) == NULL) { 
        return(VA_USER_DOES_NOT_EXIST);
    }

    getcwd(TmpBuf1, MAX_BUFF);

    if ( domain == NULL || domain[0] == 0 ) {
    	if ( chdir(VPOPMAILDIR) != 0 ) {
	    return(VA_BAD_V_DIR);
	}
        if ( chdir("users") != 0 ) {
            chdir(TmpBuf1);
            return(VA_BAD_U_DIR);
        }
        del_user_assign( user );
	uid = VPOPMAILUID;
	gid = VPOPMAILGID;
    } else {
    	tmpstr = vget_assign(domain, Dir, 156, &uid, &gid );
        if ( chdir(Dir) != 0 ) {
            chdir(TmpBuf1);
            return(VA_BAD_D_DIR);
        }

        if ( chdir("..") != 0 ) {
            chdir(TmpBuf1);
            return(VA_BAD_D_DIR);
        }
    }
    vauth_deluser( user, domain );
    dec_dir_control(domain, uid, gid);

    /* remove the users directory from the file system 
     * and check for error
     */
    if ( vdelfiles(passent->pw_dir) != 0 ) {
	printf("could not remove %s\n", passent->pw_dir);
	return(VA_BAD_DIR);
    }

    /* go back to the callers directory */
    chdir(TmpBuf1);
    return(VA_SUCCESS);

}

/*
 * make all characters in a string be lower case
 */
void lowerit( instr )
 char *instr;
{
 int size;

    if (instr==NULL) return;
    for(size=0;*instr!=0;++instr,++size ) {
        if (isupper((int)*instr)) {
            *instr = tolower(*instr);
        }

        /* add alittle size protection */
        if ( size == 156 ) {
            *instr = 0;
            return;
        }
    } 
}

int update_file(filename, update_line)
 char *filename;
 char *update_line;
{
 FILE *fs = NULL;
 FILE *fs1 = NULL;
#ifdef FILE_LOCKING
 FILE *fs3 = NULL;
#endif
 static char tmpbuf[MAX_BUFF];
 static char tmpbuf1[MAX_BUFF];
 int user_assign = 0;
 int i;

#ifdef FILE_LOCKING
    snprintf(tmpbuf, MAX_BUFF, "%s.lock", filename);
    fs3 = fopen(tmpbuf, "w+");
	if ( get_write_lock(fs3) < 0 ) return(-1);
#endif

    snprintf(tmpbuf, MAX_BUFF, "%s.%lu", filename, (long unsigned)getpid());
    fs1 = fopen(tmpbuf, "w+");
    if ( fs1 == NULL ) {
#ifdef FILE_LOCKING
		unlock_lock(fileno(fs3), 0, SEEK_SET, 0);
		fclose(fs3);
        return(VA_COULD_NOT_UPDATE_FILE);
#endif
    }

    snprintf(tmpbuf, MAX_BUFF, "%s", filename);
    if ( (fs = fopen(tmpbuf, "r+")) == NULL ) {
        if ( (fs = fopen(tmpbuf, "w+")) == NULL ) {
			fclose(fs1);
#ifdef FILE_LOCKING
			fclose(fs3);
			unlock_lock(fileno(fs3), 0, SEEK_SET, 0);
#endif
            return(VA_COULD_NOT_UPDATE_FILE);
        }
    }

    while( fgets(tmpbuf,200,fs) != NULL ) {
        strncpy(tmpbuf1, tmpbuf, MAX_BUFF);
        for(i=0;tmpbuf[i]!=0;++i) if (tmpbuf[i]=='\n') tmpbuf[i]=0;
        /* special case for users/assign */
        if ( strcmp(tmpbuf,".") == 0 ) {
            fprintf(fs1, "%s\n", update_line);
            user_assign = 1;
        } else if ( strcmp(tmpbuf,update_line) != 0 ) {
            fputs(tmpbuf1, fs1);
        }
    }

    if ( user_assign == 1 ) fprintf(fs1, ".\n");
    else fprintf(fs1, "%s\n", update_line);

    fclose(fs);
    fclose(fs1);

    snprintf(tmpbuf, MAX_BUFF, "%s", filename);
    snprintf(tmpbuf1, MAX_BUFF, "%s.%lu", filename, (long unsigned)getpid());

    rename(tmpbuf1, tmpbuf);


#ifdef FILE_LOCKING
    unlock_lock(fileno(fs3), 0, SEEK_SET, 0);
    fclose(fs3);
#endif

    return(0);
}

/*
 * Update a users quota
 */
int vsetuserquota( char *username, char *domain, char *quota )
{
 struct vqpasswd *mypw;

    if ( strlen(username) > MAX_PW_NAME ) return(VA_USER_NAME_TOO_LONG);
    if ( strlen(username) == 1 ) return(VA_ILLEGAL_USERNAME);
    if ( strlen(domain) > MAX_PW_DOMAIN ) return(VA_DOMAIN_NAME_TOO_LONG);
    if ( strlen(quota) > MAX_PW_QUOTA )    return(VA_QUOTA_TOO_LONG);

    lowerit(username);
    lowerit(domain);
    vauth_setquota( username, domain, quota);
    mypw = vauth_getpw( username, domain );
    remove_maildirsize(mypw->pw_dir);
    return(0);
}

/*
 * count the lines in /var/qmail/control/rcpthosts
 */
int count_rcpthosts()
{
 static char tmpstr1[MAX_BUFF];
 FILE *fs;
 int count;

    snprintf(tmpstr1, MAX_BUFF, "%s/control/rcpthosts", QMAILDIR);
    fs = fopen(tmpstr1, "r");
    if ( fs == NULL ) return(0);

    count = 0;
    while( fgets(tmpstr1, MAX_BUFF, fs) != NULL ) ++count;

    fclose(fs);
    return(count);

}

/*
 * compile the morercpthosts file using qmail-newmrh program
 */
int compile_morercpthosts()
{
 int pid;

    pid=vfork();
    if ( pid==0){
        execl(QMAILNEWMRH,"qmail-newmrh", NULL);
        exit(127);
    } else {
        wait(&pid);
    }
    return(0);
}

/*
 * fill out a passwd structure from then next
 * line in a file 
 */ 
struct vqpasswd *vgetent(FILE *pw)
{
    static struct vqpasswd pwent;
    static char line[200];
    int i=0,j=0;
    char *tmpstr;
    char *tmpstr1;

    if (fgets(line,sizeof(line),pw) == NULL) return NULL;

    for (i=0; line[i] != 0; i++) if (line[i] == ':') j++;

#ifdef CLEAR_PASS
    /* Must count the clear password field */
    if ( j != 7) return NULL;
#else
    if ( j != 6) return NULL;
#endif

    tmpstr = line;
    pwent.pw_name   = line;
    while (*tmpstr!=0 && *tmpstr!=':') ++tmpstr;
    *tmpstr = 0; ++tmpstr;

    pwent.pw_passwd = tmpstr;
    while (*tmpstr!=0 && *tmpstr!=':') ++tmpstr;
    *tmpstr = 0; ++tmpstr;
 
    tmpstr1 = tmpstr; 
    while (*tmpstr!=0 && *tmpstr!=':') ++tmpstr;
    *tmpstr = 0; ++tmpstr;
    pwent.pw_uid = atoi(tmpstr1); 

    tmpstr1 = tmpstr; 
    while (*tmpstr!=0 && *tmpstr!=':') ++tmpstr;
    *tmpstr = 0; ++tmpstr;
    pwent.pw_gid = atoi(tmpstr1); 


    pwent.pw_gecos  = tmpstr; 
    while (*tmpstr!=0 && *tmpstr!=':') ++tmpstr;
    *tmpstr = 0; ++tmpstr;

    pwent.pw_dir    = tmpstr; 
    while (*tmpstr!=0 && *tmpstr!=':') ++tmpstr;
    *tmpstr = 0; ++tmpstr;

    pwent.pw_shell  = tmpstr; 
    while (*tmpstr!=0 && *tmpstr!=':' && *tmpstr!='\n') ++tmpstr;
    *tmpstr = 0; ++tmpstr;

#ifdef CLEAR_PASS
    pwent.pw_clear_passwd  = tmpstr; 
    while (*tmpstr!=0 && *tmpstr!=':' && *tmpstr!='\n') ++tmpstr;
    *tmpstr = 0; ++tmpstr;
#endif

    return &pwent;
}

/*
 * figure out where to put the user and
 * make the directories if needed
 */
char *make_user_dir(char *username, char *domain, uid_t uid, gid_t gid)
{
 char *tmpstr;
 char *tmpbuf;
 char *tmpdir;
 struct vqpasswd *mypw;

    verrori = 0;
    tmpbuf = malloc(MAX_BUFF);
    getcwd(tmpbuf, MAX_BUFF);

    tmpdir = malloc(MAX_BUFF);
    vget_assign(domain, tmpdir, MAX_BUFF, NULL, NULL); 
    chdir(tmpdir); 

    open_big_dir(domain, uid, gid);
    tmpstr = next_big_dir(uid, gid);
    close_big_dir(domain, uid, gid);
    chdir(tmpstr);

  
    if ( mkdir(username, VPOPMAIL_DIR_MODE) != 0 ) {
      verrori = VA_EXIST_U_DIR;
      return(NULL);
    }

    if ( chdir(username) != 0 ) {
        chdir(tmpbuf); free(tmpbuf); free(tmpdir);
	printf( "make_user_dir: error 2\n");
        return(NULL);
    }

    if (mkdir("Maildir",VPOPMAIL_DIR_MODE) == -1){ 
        chdir(tmpbuf); free(tmpbuf); free(tmpdir);
	printf("make_user_dir: error 3\n");
        return(NULL);
    }

    if (chdir("Maildir") == -1) { 
        chdir(tmpbuf); free(tmpbuf); free(tmpdir);
	printf("make_user_dir: error 4\n");
        return(NULL);
    }

    if (mkdir("cur",VPOPMAIL_DIR_MODE) == -1) {  
        chdir(tmpbuf); free(tmpbuf); free(tmpdir);
	printf("make_user_dir: error 5\n");
        return(NULL);
    }

    if (mkdir("new",VPOPMAIL_DIR_MODE) == -1) { 
        chdir(tmpbuf); free(tmpbuf); free(tmpdir);
	printf("make_user_dir: error 6\n");
        return(NULL);
    }

    if (mkdir("tmp",VPOPMAIL_DIR_MODE) == -1) {  
        chdir(tmpbuf); free(tmpbuf); free(tmpdir);
	printf("make_user_dir: error 7\n");
        return(NULL);
    }

    chdir("../..");
    r_chown(username, uid, gid);

    mypw = vauth_getpw( username, domain);
    if ( mypw == NULL ) { 
    	chdir(tmpbuf); free(tmpbuf); free(tmpdir);
	return(tmpstr);
    }

    mypw->pw_dir = malloc(MAX_BUFF);
    if ( strlen(tmpstr) > 0 ) {
	snprintf(mypw->pw_dir, 156, "%s/%s/%s", tmpdir, tmpstr, username);
    } else {
	snprintf(mypw->pw_dir, 156, "%s/%s", tmpdir, username);
    }
    vauth_setpw( mypw, domain );

#ifdef SQWEBMAIL_PASS
    if ( mypw != NULL ) {
	vsqwebmail_pass( mypw->pw_dir, mypw->pw_passwd, uid, gid);
    }
#endif

    chdir(tmpbuf); free(tmpbuf); free(tmpdir);
    return(tmpstr);
}

int r_mkdir(char *path, uid_t uid, gid_t gid )
{
 static char tmpbuf[MAX_DIR_NAME];
 int i;

    for(i=0;path[i]!=0;++i){
        if ( path[i] == '/' ) {
            tmpbuf[i] = 0;
            mkdir(tmpbuf,VPOPMAIL_DIR_MODE);
            chown(tmpbuf, uid, gid);
        }
        tmpbuf[i] = path[i];
    }
    mkdir(path,VPOPMAIL_DIR_MODE);
    chown(path, uid, gid);
    return(0);
}

int pw_comp(char *supp, char *curr, char *apop, int type)
{
    /* Type can be: 0 -- try both APOP and user/passwd
            1 -- user/passwd only
            2 -- only do an APOP check
       If only APOP or PASSWD auth is compiled in (ie, not both), then the
       type field is ignored.
    */
#ifdef APOP
    char buf[100];
    unsigned char digest[16];
    char ascii[33];
    MD5_CTX context;
#endif

#ifdef DEBUG
    fprintf (stderr,"pw_comp: on entry: %s -- %s -- %s -- %d\n",supp,curr,apop,type);
#endif

#ifndef APOP
    type = 1;
#endif

/*
#ifndef ENABLE_PASSWD
    type = 2;
#endif
*/

#ifdef APOP
    memset(ascii,0,sizeof(ascii));
    if (type != 1) {
        strncpy(buf,apop,sizeof(buf));
        strncat(buf,curr,sizeof(buf));
#ifdef DEBUG
        fprintf (stderr,"pw_comp: making digest for %s\n",buf);
#endif
        MD5Init (&context);
        MD5Update (&context,buf,strlen(buf));
        MD5Final (digest, &context);
        strncpy(ascii,dec2hex(digest),sizeof(ascii));
#ifdef DEBUG
        fprintf (stderr,"pw_comp: comparing digests %s and %s\n",ascii,supp);
#endif
        if (!strcmp(ascii,supp))
            return 1;
    }
#endif

    if (type != 2) {
#ifdef DEBUG
        fprintf (stderr,"pw_comp: Comparing %s (%s) with %s\n",supp,crypt(supp,curr),curr);
#endif

        if (!strcmp(curr,crypt(supp,curr))) return 2;
    }

#ifdef DEBUG
    fprintf (stderr,"pw_comp: Bugger -- nothing passwd :-/\n");
#endif
    /* If we got this far, one of the checks failed */
    return 0;
}

#ifdef APOP
char *dec2hex(unsigned char *digest)
{
    static char ascii[33];
    char *hex="0123456789abcdef";
    int i,j,k;
    memset(ascii,0,sizeof(ascii));
    for (i=0; i < 16; i++) {
        j = digest[i]/16;
        k = digest[i]%16;
        ascii[i*2] = hex[j];
        ascii[(i*2)+1] = hex[k];
    }

    return ascii;
}
#endif

struct vqpasswd *vauth_user(char *user, char *domain, char* password, char *apop)
{
 struct vqpasswd *mypw;
 char *tmpstr;
 char Dir[156];
 uid_t uid;
 gid_t gid;

    if ( password == NULL ) return(NULL);

    mypw = vauth_getpw(user, domain);
    if ( mypw == NULL ) return(NULL);

    if (pw_comp(password,mypw->pw_passwd,apop,mypw->pw_uid)==0) {
        return(NULL);
    }

    tmpstr = vget_assign(domain, Dir, 156, &uid, &gid );

    mypw->pw_uid = uid;
    mypw->pw_gid = gid;
    return(mypw);

}

/*
 * Set the default domain from either the DEFAULT_DOMAIN
 */
void vset_default_domain( char *domain ) 
{
 int i;
 char *tmpstr;
#ifdef IP_ALIAS_DOMAINS
 char host[156];
#endif

    if ( domain == 0 || strlen(domain)>0) return;

	tmpstr = getenv("VPOPMAIL_DOMAIN");
	if ( tmpstr != NULL ) {
		strncpy(domain,tmpstr,156);
		return;
	}
#ifdef IP_ALIAS_DOMAINS
	tmpstr = getenv("TCPLOCALIP");
	memset(host,0,156);
	if ( vget_ip_map(tmpstr,host,156)==0 && !host_in_locals(host)){
		if ( strlen(host) > 0 ) {
			strncpy( domain, host, 156 );
		}
		return;
	}
#endif

	if ( (i=strlen(DEFAULT_DOMAIN)) > 0 ) {
		strncpy(domain,DEFAULT_DOMAIN, i+1);
    }
}

#ifdef IP_ALIAS_DOMAINS
int host_in_locals(domain)
 char *domain;
{
 int i;
	char *tmpbuf;
 	FILE *fs;

	tmpbuf = malloc(200);
	
	snprintf(tmpbuf, 200, "%s/control/locals", QMAILDIR);
	fs = fopen(tmpbuf,"r");
	if ( fs == NULL ) {
		free(tmpbuf);
		return(0);
	}

	while( fgets(tmpbuf,200,fs) != NULL ) {
		for(i=0;tmpbuf[i]!=0;++i) if (tmpbuf[i]=='\n') tmpbuf[i]=0;
		if ( strcmp( domain, tmpbuf ) == 0 ) {
			free(tmpbuf);
			fclose(fs);
			return(1);
		}
		if ( strcmp(domain, "localhost") == 0 && 
			 strstr(domain,"localhost") != NULL ) {
			free(tmpbuf);
			fclose(fs);
			return(1);
		}
	}

	free(tmpbuf);
	fclose(fs);
	return(0);
}
#endif

char *verror(int va_err )
{
    switch(va_err) {
      case VA_SUCCESS:
          return("Success");
      case VA_ILLEGAL_USERNAME:
          return("Illegal username");
      case VA_USERNAME_EXISTS:
          return("Username exists");
      case VA_BAD_DIR:
          return("Unable to chdir to vpopmail directory");
      case VA_BAD_U_DIR:
          return("Unable to chdir to vpopmail/users directory");
      case VA_BAD_D_DIR:
          return("Unable to chdir to vpopmail/" DOMAINS_DIR " directory");
      case VA_BAD_V_DIR:
          return("Unable to chdir to vpopmail/" DOMAINS_DIR "/domain directory");
      case VA_EXIST_U_DIR:
          return("User's directory already exists?");
      case VA_BAD_U_DIR2:
          return("Unable to chdir to user's directory");
      case VA_SUBDIR_CREATION:
          return("Creation of user's subdirectories failed?");
      case VA_USER_DOES_NOT_EXIST:
          return("User does not exist");
      case VA_DOMAIN_DOES_NOT_EXIST:
          return("Domain does not exist");
      case VA_INVALID_DOMAIN_NAME:
          return("Invalid domain name");
      case VA_DOMAIN_ALREADY_EXISTS:
          return("Domain already exists");
      case VA_COULD_NOT_MAKE_DOMAIN_DIR:
          return("Could not make domain dir");
      case VA_COULD_NOT_OPEN_QMAIL_DEFAULT:
          return("Could not open qmail default");
      case VA_CAN_NOT_MAKE_DOMAINS_DIR:
          return("Can not make " DOMAINS_DIR " directory");
      case VA_COULD_NOT_UPDATE_FILE:
          return("Could not update file");
      case VA_CRYPT_FAILED:
          return("Crypt failed");
      case VA_COULD_NOT_OPEN_DOT_QMAIL:
          return("Could not open dot qmail file");
      case VA_BAD_CHAR:
          return("bad character");
      case VA_BAD_UID:
          return("running as invalid uid");
      case VA_NO_AUTH_CONNECTION:
          return("no auth connection");
      case VA_MEMORY_ALLOC_ERR:
          return("memory allocation error");
      case VA_USER_NAME_TOO_LONG:
          return("user name too long");
      case VA_DOMAIN_NAME_TOO_LONG:
          return("domain name too long");
      case VA_PASSWD_TOO_LONG:
          return("password too long");
      case VA_GECOS_TOO_LONG:
          return("gecos too long");
      case VA_QUOTA_TOO_LONG:
          return("quota too long");
      case VA_DIR_TOO_LONG:
          return("dir too long");
      case VA_CLEAR_PASSWD_TOO_LONG:
          return("clear password too long");
      case VA_ALIAS_LINE_TOO_LONG:
          return("alias line too long");
      case VA_NULL_POINTER:
          return("null pointer");
      case VA_INVALID_EMAIL_CHAR:
          return("invalid email character");
      default:
          return("Unknown error");
    }

}

int vadddotqmail( char *alias, char *domain,... ) 
{
 struct vqpasswd *mypw = NULL; 
 FILE *fs;
 va_list args;
 char *email;
 char Dir[156];
 uid_t uid;
 gid_t gid;
 char *tmpstr;

    tmpstr = vget_assign(domain, Dir, 156, &uid, &gid );
    snprintf(TmpBuf1, 200, "%s/.qmail-%s", Dir, alias);
    if ((fs=fopen(TmpBuf1, "w")) == NULL) return(VA_COULD_NOT_OPEN_DOT_QMAIL);

    va_start(args,domain);
    while ( (email=va_arg(args, char *)) != NULL ) {
        if ( strstr(email, "@") == NULL ) {
            mypw = vauth_getpw( email, domain );
            if ( mypw == NULL ) return(VA_USER_DOES_NOT_EXIST);
            fprintf(fs, "%s/Maildir/\n", mypw->pw_dir);
        } else {
            fprintf(fs, "%s\n", email);
        }
    }
    fclose(fs);

    snprintf(TmpBuf1, MAX_BUFF, "%s/.qmail-%s", Dir, alias);
    chown(TmpBuf1,uid,gid);
    printf("%s\n", TmpBuf1);

    va_end(args);
    return(VA_SUCCESS);
}

int vdeldotqmail( char *alias, char *domain )
{
 char Dir[156];
 uid_t uid;
 gid_t gid;
 char *tmpstr;

    tmpstr = vget_assign(domain, Dir, 156, &uid, &gid );
    snprintf(TmpBuf1, MAX_BUFF, "%s/.qmail-%s", Dir, alias);
    if ( unlink(TmpBuf1) < 0 ) {
        return(VA_COULD_NOT_OPEN_DOT_QMAIL);
    }
    return(VA_SUCCESS);
}

/*
 * Given the domain name:
 * 
 * Fill in dir, uid, gid if not passed as NULL
 * And return the name of the domain on success
 * or return NULL if the domain does not exist.
 *
 * get uid, gid, dir from users/assign with caching
 */
char *vget_assign(char *domain, char *dir, int dir_len, uid_t *uid, gid_t *gid)
{
 FILE *fs;
 int dlen;
 int i;
 char *ptr;
 char *tmpstr;
 int  mem_size;
 char *tmpbuf;
 char tmpbuf2[200];
 static char *in_domain = NULL;
 static int in_domain_size = 0;
 static char *in_dir = NULL;
 static int in_dir_size = 0;
 static uid_t in_uid = -1;
 static gid_t in_gid = -1;

    if ( domain == NULL || *domain == 0) return(NULL);

    lowerit(domain);
    if ( in_domain_size != 0 && 
         in_domain!=NULL && in_dir!=NULL &&
         strncmp( in_domain, domain, in_domain_size )==0 ){
        if ( uid!=NULL ) *uid = in_uid;
        if ( gid!=NULL ) *gid = in_gid;
        if ( dir!=NULL ) strncpy( dir, in_dir, dir_len);
        return(in_dir);
    }

    if ( in_domain != NULL ) free(in_domain);

    in_domain_size = strlen(domain)+3;
    in_domain = malloc(in_domain_size);
    strncpy(in_domain, domain, in_domain_size);

    mem_size = strlen(domain) + 3;
    tmpstr = malloc(mem_size);
    strncpy(tmpstr, "!", mem_size);
    strncat(tmpstr, domain, mem_size);
    strncat(tmpstr, "-", mem_size);

    snprintf(tmpbuf2, 200, "%s/users/cdb", QMAILDIR);
    if ( (fs = fopen(tmpbuf2, "r")) == 0 ) {
        free(tmpstr);
        return(NULL);
    }
    i = cdb_seek(fileno(fs), tmpstr, mem_size-1, &dlen);
    in_uid = -1;
    in_gid = -1;
    if ( i == 1 ) {
        tmpbuf = malloc(dlen);
        i = fread(tmpbuf,sizeof(char),dlen,fs);

        /* get the domain line */
        strcpy(domain, tmpbuf);

        /* get the uid */
        ptr = tmpbuf;
        while( *ptr != 0 ) ++ptr;
        ++ptr;
        in_uid = atoi(ptr);
        if ( uid!=NULL) *uid = in_uid;

        /* get the gid */
        while( *ptr != 0 ) ++ptr;
        ++ptr;
        in_gid = atoi(ptr);
        if ( gid!=NULL) *gid = in_gid;

        while( *ptr != 0 ) ++ptr;
        ++ptr;

        if ( dir!=NULL ) strncpy( dir, ptr, dir_len);
        if ( in_dir != NULL ) free(in_dir);
        in_dir_size = strlen(ptr)+1;
        in_dir = malloc(in_dir_size);
        strncpy( in_dir, ptr, in_dir_size);

        free(tmpstr);
        free(tmpbuf);
	fclose(fs);
        return(in_dir);
    } else {
        if ( in_domain != NULL ) free(in_domain);
        in_domain = NULL;
        in_domain_size = 0;
    }
    fclose(fs);
    free(tmpstr);
    return(NULL);

}

int vget_real_domain(char *domain, int len )
{
 char *tmpstr;
 char Dir[156];
 uid_t uid;
 gid_t gid;
 int i;

    if ( domain == NULL ) return(0);

    /* process the default domain 
    if ( domain[0] == 0 ) {
        if ( strlen(DEFAULT_DOMAIN) > 0 ) {
            strncpy(domain, DEFAULT_DOMAIN, len);
            return(0);
        }
        return(0);
    }
    */

    tmpstr = vget_assign(domain, Dir, 156, &uid, &gid );
    if ( tmpstr == NULL ) return(0);

    for(gid=strlen(Dir),uid=gid;Dir[uid]!='/';--uid);
    for(i=0,++uid;Dir[uid]!=0&&uid<gid;++uid,++i) domain[i] = Dir[uid];
    domain[i] = 0;

    return(0);
}

int vmake_maildir(char *domain, char *dir )
{
 char tmpbuf[156];
 char tmpbuf2[156];
 uid_t uid;
 gid_t gid;
 char *tmpstr;
 int i;

    getcwd(tmpbuf2, 156);

    /* set the mask for file creation */
    umask(VPOPMAIL_UMASK);
 
    if ( vget_assign(domain, tmpbuf, 156, &uid, &gid ) == NULL ) {
      return( VA_DOMAIN_DOES_NOT_EXIST );
    }

    /* walk to where the sub directory starts */
    for(i=0,tmpstr=dir;tmpbuf[i]==*tmpstr&&tmpbuf[i]!=0&&*dir!=0;++i,++tmpstr);

    /* walk past trailing slash */
    while ( *tmpstr == '/'  ) ++tmpstr;

    if ( chdir(tmpbuf) == -1 ) {
      return( VA_BAD_DIR);
    }

    /* automatically create the sub directories */
    r_mkdir(tmpstr, uid, gid);

    /* create the Maildir */
    if ( chdir(dir) != 0 ) return(-1);
    if (mkdir("Maildir",VPOPMAIL_DIR_MODE) == -1) return(-1);
    if (chdir("Maildir") == -1) return(-1);
    if (mkdir("cur",VPOPMAIL_DIR_MODE) == -1) return(-1);
    if (mkdir("new",VPOPMAIL_DIR_MODE) == -1) return(-1);
    if (mkdir("tmp",VPOPMAIL_DIR_MODE) == -1) return(-1);
    chdir(dir);
    r_chown(dir, uid, gid);
    chdir(dir);

    /* change back to the orignal dir */
    chdir(tmpbuf2);
    return(0);
}

int vsqwebmail_pass( char *dir, char *crypted, uid_t uid, gid_t gid )
{
 FILE *fs;

	if ( dir == NULL ) return(VA_SUCCESS);
    snprintf(TmpBuf2, MAX_BUFF, "%s/Maildir/sqwebmail-pass", dir);
    if ( (fs = fopen(TmpBuf2, "w")) != NULL ) {
        fprintf(fs, "\t%s\n", crypted);
        fclose(fs);
        chown(TmpBuf2,uid,gid);
        return(0);
    }
    return(VA_SQWEBMAIL_PASS_FAIL);
}

#ifdef POP_AUTH_OPEN_RELAY 
int open_smtp_relay()
{
#ifdef USE_SQL
	vopen_smtp_relay();	
	update_rules();
#else
 FILE *fs;
 FILE *fs1;
#ifdef FILE_LOCKING
 FILE *fs3;
#endif
 char *ipaddr;
 char *tmpstr;
 time_t mytime;
 int rebuild_cdb = 1;
 char tmpbuf[156];


	mytime = time(NULL);
#ifdef FILE_LOCKING
	if ( (fs3=fopen(OPEN_SMTP_LOK_FILE, "w+")) == NULL) return(-1);
	get_write_lock(fs3);
#endif

	if ( (fs = fopen(OPEN_SMTP_CUR_FILE, "r+")) == NULL ) {
		if ( (fs = fopen(OPEN_SMTP_CUR_FILE, "w+")) == NULL ) {
#ifdef FILE_LOCKING
			unlock_lock(fileno(fs3), 0, SEEK_SET, 0);
			fclose(fs3);
#endif
			return(0);
		}
	}
	snprintf(tmpbuf, 156, 
            "%s.%lu", OPEN_SMTP_TMP_FILE, (long unsigned)getpid());
	fs1 = fopen(tmpbuf, "w+");

	if ( fs1 == NULL ) {
#ifdef FILE_LOCKING
		unlock_lock(fileno(fs3), 0, SEEK_SET, 0);
		fclose(fs3);
#endif
		return(0);
	}

	ipaddr = getenv("TCPREMOTEIP");

	/* courier-imap mangles TCPREMOTEIP */
	if ( ipaddr != NULL &&  ipaddr[0] == ':') {
		ipaddr +=2;
		while(*ipaddr!=':') ++ipaddr;
		++ipaddr;
	}

	if ( ipaddr == NULL ) {
#ifdef FILE_LOCKING
		unlock_lock(fileno(fs3), 0, SEEK_SET, 0);
		fclose(fs3);
#endif
		return(0);
	}

	while ( fgets(TmpBuf1, 100, fs ) != NULL ) {
		strncpy(TmpBuf2, TmpBuf1, BUFF_SIZE);
		tmpstr = strtok( TmpBuf2, ":");
		if ( strcmp( tmpstr, ipaddr ) != 0 ) {
			fputs(TmpBuf1, fs1);
		} else {
			rebuild_cdb = 0;
		}
	}
	fprintf( fs1, "%s:allow,RELAYCLIENT=\"\",RBLSMTPD=\"\"	 %d\n", 
		ipaddr, (int)mytime);
	fclose(fs);
	fclose(fs1);

	rename(tmpbuf, OPEN_SMTP_CUR_FILE);
	if ( rebuild_cdb ) update_rules();

#ifdef FILE_LOCKING
	unlock_lock(fileno(fs3), 0, SEEK_SET, 0);
	fclose(fs3);
#endif
#endif
	return(0);
}
#endif


#ifdef POP_AUTH_OPEN_RELAY 
long unsigned tcprules_open()
{
 int pim[2];
 long unsigned pid;

	memset(bin0,0,BUFF_SIZE);
	memset(bin1,0,BUFF_SIZE);
	memset(bin2,0,BUFF_SIZE);
	snprintf(relay_template, 300, "tmp.%ld", (long unsigned)getpid());

	if (pipe(pim) == -1)  { return(-1);}

	switch( pid=vfork()){
	case -1:
		close(pim[0]); close(pim[1]);
		return(-1);
	case 0:
		close(pim[1]);
		if (vfd_move(0,pim[0]) == -1) _exit(120);
		strncpy(bin0, TCPRULES_PROG, BUFF_SIZE);
		strncpy( bin1, TCP_FILE, BUFF_SIZE);
		strncat( bin1, ".cdb", BUFF_SIZE);
		strncpy( bin2, TCP_FILE, BUFF_SIZE);
		strncat( bin2, relay_template, BUFF_SIZE);
		binqqargs[0] = bin0;
		binqqargs[1] = bin1;
		binqqargs[2] = bin2;
		binqqargs[3] = 0;
		execv(*binqqargs,binqqargs);
	}

	fdm = pim[1]; close(pim[0]);
	return(pid);
}
#endif

int vfd_copy(to,from)
int to;
int from;
{
  if (to == from) return 0;
  if (fcntl(from,F_GETFL,0) == -1) return -1;
  close(to);
  if (fcntl(from,F_DUPFD,to) == -1) return -1;
  return 0;
}
int vfd_move(int to, int from)
{
  if (to == from) return 0;
  if (vfd_copy(to,from) == -1) return -1;
  close(from);
  return 0;
}

#ifdef POP_AUTH_OPEN_RELAY 
int update_rules()
{
 FILE *fs;
 long unsigned pid;
 int wstat;
#ifndef USE_SQL
 char *tmpstr;
#endif

	umask(VPOPMAIL_TCPRULES_UMASK);
	if ((pid = tcprules_open()) < 0) {
		return(-1);
	}

#ifdef USE_SQL
	vupdate_rules(fdm);
#else
	fs = fopen(OPEN_SMTP_CUR_FILE, "r");
	if ( fs != NULL ) {
		while ( fgets(TmpBuf1, 100, fs ) != NULL ) {
			strncpy(TmpBuf2, TmpBuf1, BUFF_SIZE);
			tmpstr = strtok( TmpBuf2, "\t");
			strncat(tmpstr, "\n", BUFF_SIZE);
			write(fdm,tmpstr, strlen(tmpstr));
		}
		fclose(fs);
	}
#endif

	fs = fopen(TCP_FILE, "r");
	if ( fs != NULL ) {
		while ( fgets(TmpBuf1, 100, fs ) != NULL ) {
			write(fdm,TmpBuf1, strlen(TmpBuf1));
		}
		fclose(fs);
	}
	close(fdm);	

	/* wait untill tcprules finishes so we don't have zombies */
	while(wait(&wstat)!= pid);

        /* unlink the temp file in case tcprules has an error */
        if ( unlink(relay_template) == -1 ) {
		return(-1);
        }

	/* Set the ownership of the file */
	snprintf(TmpBuf1, MAX_BUFF, "%s.cdb", TCP_FILE);
	chown(TmpBuf1,VPOPMAILUID,VPOPMAILGID);

        return(0);
}
#endif

char *vversion(char *outbuf)
{
	if ( outbuf != NULL ) strcpy(outbuf, VERSION);
	return(VERSION);
}

int vexit(int err)
{
    vclose();
    exit(err);
}

void remove_maildirsize(char *dir) {
 char maildirsize[500];
 FILE *fs;

    sprintf(maildirsize, "%s/Maildir/maildirsize", dir);
    if ( (fs = fopen(maildirsize, "r+"))!=NULL) {
        fclose(fs);
        unlink(maildirsize);
    }
}

int vcheck_vqpw(struct vqpasswd *inpw, char *domain)
{

  if ( inpw == NULL )   return(VA_NULL_POINTER );
  if ( domain == NULL ) return(VA_NULL_POINTER);

  if ( inpw->pw_name == NULL )         return(VA_NULL_POINTER);
  if ( inpw->pw_passwd == NULL )       return(VA_NULL_POINTER);
  if ( inpw->pw_gecos == NULL )        return(VA_NULL_POINTER);
  if ( inpw->pw_dir == NULL )          return(VA_NULL_POINTER);
  if ( inpw->pw_shell == NULL )        return(VA_NULL_POINTER);
  if ( inpw->pw_clear_passwd == NULL ) return(VA_NULL_POINTER);

  if ( strlen(inpw->pw_name) > MAX_PW_NAME )   return(VA_USER_NAME_TOO_LONG);
  if ( strlen(inpw->pw_name) == 1 )            return(VA_ILLEGAL_USERNAME);
  if ( strlen(domain) > MAX_PW_DOMAIN )        return(VA_DOMAIN_NAME_TOO_LONG);
  if ( strlen(inpw->pw_passwd) > MAX_PW_PASS ) return(VA_PASSWD_TOO_LONG);
  if ( strlen(inpw->pw_gecos) > MAX_PW_PASS )  return(VA_GECOS_TOO_LONG);
  if ( strlen(inpw->pw_dir) > MAX_PW_DIR )     return(VA_DIR_TOO_LONG);
  if ( strlen(inpw->pw_shell) > MAX_PW_QUOTA ) return(VA_QUOTA_TOO_LONG);
  if ( strlen(inpw->pw_clear_passwd) > MAX_PW_CLEAR_PASSWD )
                                               return(VA_CLEAR_PASSWD_TOO_LONG);
  return(VA_SUCCESS);

}

char *vgen_pass(int len)
{
  int gen_char_len = 0; 
  int i = 0; 
  int k = 0; 
  char *p = NULL;

  gen_char_len = strlen(gen_chars);

  p = malloc(len + 1);
  if (p == NULL) return NULL;

  srand(rand() % time(NULL) ^ getpid());

  memset((char *)p, len, 0);

  for (i = 0; i < len; i++) {
      k = rand()%gen_char_len;
      p[i] = gen_chars[k];
  }
  return p;

}

int vvalidchar( char inchar ) 
{
 
 /* check lower case a to lower case z */
 if ( inchar >= 'a' && inchar <= 'z' ) return(1);

 /* check upper case a to upper case z */
 if ( inchar >= 'A' && inchar <= 'Z' ) return(1);

 /* check numbers */
 if ( inchar >= '0' && inchar <= '9' ) return(1);

 /* check for '-' and '.' */
 if ( inchar == '-' || inchar == '.' || inchar == '_' ) return(1);

 /* everything else is invalid */
 verrori = VA_INVALID_EMAIL_CHAR;
 return(0);
 
}

/* support all the valid characters except %
 * which might be exploitable in a printf
 */
int is_username_valid( char *user ) 
{
  while(*user != 0 ) {
    if ( (*user == 33) || 
         (*user == 35 ) || 
         (*user == 36 ) || 
         (*user == 38 ) || 
         (*user == 39 ) || 
         (*user == 42 ) || (*user == 43) ||
         (*user >= 45 && *user <= 57) ||
         (*user == 61 ) || (*user == 63 ) ||
         (*user >= 65 && *user <= 90) ||
         (*user >= 94 && *user <= 126 ) ) {
      ++user;
    } else {
      return(VA_ILLEGAL_USERNAME);
    }
  }
  return(0);
}

int is_domain_valid( char *domain ) 
{
  while(*domain != 0 ) {
    if ( (*domain == 45) || (*domain == 46) || 
         (*domain >= 48 && *domain <= 57) ||
         (*domain >= 65 && *domain <= 90) ||
         (*domain >= 97 && *domain <= 122) ) {
      ++domain;
    } else {
      return(VA_INVALID_DOMAIN_NAME);
    }
  }
  return(0);
}

int vaddaliasdomain( char *alias_domain, char *real_domain)
{
 char *tmpstr;
 uid_t uid;
 gid_t gid;
 static char Dir[156];
 int err;

    lowerit(alias_domain);
    lowerit(real_domain);

    if ( (err=is_domain_valid(real_domain)) != VA_SUCCESS ) return(err);
    if ( (err=is_domain_valid(alias_domain)) != VA_SUCCESS ) return(err);

    tmpstr = vget_assign(alias_domain, Dir, 156, &uid, &gid);
    if ( tmpstr != NULL ) return(VA_DOMAIN_ALREADY_EXISTS);

    tmpstr = vget_assign(real_domain, Dir, 156, &uid, &gid);
    if ( tmpstr == NULL ) return(VA_DOMAIN_DOES_NOT_EXIST);

    add_domain_assign( alias_domain, real_domain, Dir, uid, gid );
    signal_process("qmail-send", SIGHUP);

    return(VA_SUCCESS);
}
