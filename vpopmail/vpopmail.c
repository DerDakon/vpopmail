/*
 * $Id: vpopmail.c,v 1.31 2004-03-14 18:00:40 kbo Exp $
 * Copyright (C) 2000-2004 Inter7 Internet Technologies, Inc.
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
#include "vlimits.h"
#include "maildirquota.h"

#define MAX_BUFF 256

#ifdef POP_AUTH_OPEN_RELAY
/* keep a output pipe to tcp.smtp file */
int tcprules_fdm;
static char relay_tempfile[MAX_BUFF];
#endif

int verrori = 0;

extern int cdb_seek();

/* Global Flags */
int NoMakeIndex = 0;
int OptimizeAddDomain = 0;

#define PS_TOKENS " \t"
#define CDB_TOKENS ":\n\r"


#ifdef IP_ALIAS_DOMAINS
int host_in_locals(char *domain);
#endif

static char gen_chars[] = "abcdefghijklmnopqrstuvwxyz" \
                          "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
                          "0123456789.@!#%*";

static char ok_env_chars[] = "abcdefghijklmnopqrstuvwxyz" \
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
                            "1234567890_-.@";

/************************************************************************/

/* 
 * Add a domain to the email system
 *
 * input: domain name
 *        dir to put the files
 *        uid and gid to assign to the files
 */
int vadddomain( char *domain, char *dir, uid_t uid, gid_t gid )
{
 FILE *fs;
 int i;
 char *domain_hash;
 char DomainSubDir[MAX_BUFF];
 char dir_control_for_uid[MAX_BUFF];
 char tmpbuf[MAX_BUFF];
 char Dir[MAX_BUFF];
 char calling_dir[MAX_BUFF];

  /* we only do lower case */
  lowerit(domain);

  /* reject domain names that are too short to be valid */
  if ( strlen( domain) <3) return (VA_INVALID_DOMAIN_NAME);

  /* reject domain names that exceed our max permitted/storable size */
  if ( strlen( domain ) >= MAX_PW_DOMAIN ) return(VA_DOMAIN_NAME_TOO_LONG);

  /* check invalid email domain characters */
  for(i=0;domain[i]!=0;++i) {
    if (i == 0 && domain[i] == '-' ) return(VA_INVALID_DOMAIN_NAME);
    if (isalnum((int)domain[i])==0 && domain[i]!='-' && domain[i]!='.') {
      return(VA_INVALID_DOMAIN_NAME);
    }
  }
  if ( domain[i-1] == '-' ) return(VA_INVALID_DOMAIN_NAME);

  /* after the name is okay, check if it already exists */
  if ( vget_assign(domain, NULL, 0, NULL, NULL ) != NULL ) {
    return(VA_DOMAIN_ALREADY_EXISTS);
  }
 
  /* set our file creation mask for machines where the
   * sysadmin has tightened default permissions
   */
  umask(VPOPMAIL_UMASK);

  /* store the calling directory */
  getcwd(calling_dir, sizeof(calling_dir));

  /* go to the directory where our Domains dir is to be stored 
   * check for error and return error on error
   */
  if ( chdir(dir) != 0 ) return(VA_BAD_V_DIR);

  /* go into the Domains subdir */
  if ( chdir(DOMAINS_DIR) != 0 ) {

    /* if it's not there, no problem, just try to create it */
    if ( mkdir(DOMAINS_DIR, VPOPMAIL_DIR_MODE) != 0 ) {
      chdir(calling_dir);
      return(VA_CAN_NOT_MAKE_DOMAINS_DIR);
    }

    /*  set the permisions on our new Domains dir */
    chown(DOMAINS_DIR,uid,gid);

    /* now try moving into the Domains subdir again */
    if ( chdir(DOMAINS_DIR) != 0 ) {
      chdir(calling_dir);
      return(VA_BAD_D_DIR);
    }
  }

  /* since domains can be added under any /etc/passwd
   * user, we have to create dir_control information
   * for each user/domain combination
   */
  snprintf(dir_control_for_uid, sizeof(dir_control_for_uid),
   "dom_%lu", (long unsigned)uid);

  /* work out a subdir name for the domain 
   * Depending on how many domains we have, it may need to be hashed
   */
  open_big_dir(dir_control_for_uid, uid, gid);       
  domain_hash = next_big_dir(uid, gid);
  close_big_dir(dir_control_for_uid, uid, gid);      

  if ( strlen(domain_hash) > 0 ) {
    snprintf(DomainSubDir, sizeof(DomainSubDir), "%s/%s", domain_hash, domain);
  } else {
    snprintf(DomainSubDir,sizeof(DomainSubDir), "%s", domain);
  }

  /* Check to make sure length of the dir isnt going to exceed
   * the maximum storable size
   * We dont want to start creating dirs and putting entries in
   * the assign file etc if the path is going to be too long
   */
  if (strlen(dir)+strlen(DOMAINS_DIR)+strlen(DomainSubDir) >= MAX_PW_DOMAIN) {
    /* back out of changes made so far */
    dec_dir_control(dir_control_for_uid, uid, gid);
    chdir(calling_dir);
    return(VA_DIR_TOO_LONG);
  }

  /* Make the subdir for the domain */
  if ( r_mkdir(DomainSubDir, uid, gid ) != 0 ) {
    /* back out of changes made so far */
    dec_dir_control(dir_control_for_uid, uid, gid);
    chdir(calling_dir);
    return(VA_COULD_NOT_MAKE_DOMAIN_DIR);
  }
  
  if ( chdir(DomainSubDir) != 0 ) {
    /* back out of changes made so far */
    vdelfiles(DomainSubDir);
    dec_dir_control(dir_control_for_uid, uid, gid);
    chdir(calling_dir);
    return(VA_BAD_D_DIR);
  }

  /* create the .qmail-default file */
  snprintf(tmpbuf, sizeof(tmpbuf), "%s/%s/%s/.qmail-default", dir, DOMAINS_DIR, 
    DomainSubDir);
  if ( (fs = fopen(tmpbuf, "w+"))==NULL) {
    /* back out of changes made so far */
    chdir(dir); chdir(DOMAINS_DIR);
    if (vdelfiles(DomainSubDir) != 0) {
      fprintf(stderr, "Failed to delete directory tree :%s\n", DomainSubDir);
    }
    dec_dir_control(dir_control_for_uid, uid, gid);
    chdir(calling_dir);
    return(VA_COULD_NOT_OPEN_QMAIL_DEFAULT);
  } else {
    fprintf(fs, "| %s/bin/vdelivermail '' bounce-no-mailbox\n", VPOPMAILDIR);
    fclose(fs);
  }

  /* create an entry in the assign file for our new domain */
  snprintf(tmpbuf, sizeof(tmpbuf), "%s/%s/%s", dir, DOMAINS_DIR, DomainSubDir);
  if (add_domain_assign( domain, domain, tmpbuf, uid, gid ) != 0) {
    /* back out of changes made so far */
    chdir(dir); chdir(DOMAINS_DIR);
    if (vdelfiles(DomainSubDir) != 0) {
      fprintf(stderr, "Failed to delete directory tree: %s\n", DomainSubDir);
    }
    dec_dir_control(dir_control_for_uid, uid, gid);
    chdir(calling_dir);
    fprintf (stderr, "Error. Failed to add domain to assign file\n");
    return (VA_COULD_NOT_UPDATE_FILE);
  }

  /* recursively change ownership to new file system entries */
  snprintf(tmpbuf, sizeof(tmpbuf), "%s/%s/%s", dir, DOMAINS_DIR, DomainSubDir);
  r_chown(tmpbuf, uid, gid);

  /* ask the authentication module to add the domain entry */
  /* until now we checked if domain already exists in cdb and
   * setup all dirs, but vauth_adddomain may __fail__ so we need to check
   */

  if (vauth_adddomain( domain ) != VA_SUCCESS ) {

    /* ok we have run into problems here. adding domain to auth backend failed
     * so now we need to reverse the steps we have already performed above 
     */

    fprintf(stderr, "Error. Failed while attempting to add domain to auth backend\n");

    chdir(dir); chdir(DOMAINS_DIR);    
    if (vdelfiles(DomainSubDir) != 0) {
      fprintf(stderr, "Failed to delete directory tree: %s\n", DomainSubDir);
    }

    dec_dir_control(dir_control_for_uid, uid, gid);

    vget_assign(domain, Dir, sizeof(Dir), &uid, &gid );

    if ( del_domain_assign(domain, domain, Dir, uid, gid) != 0) {
      fprintf(stderr, "Failed while attempting to remove domain from assign file\n");
    }

    if (del_control(domain) !=0) {
      fprintf(stderr, "Failed while attempting to delete domain from the qmail control files\n");
    }

    if (vdel_dir_control(domain) != 0) {
      fprintf (stderr, "Failed while attempting to delete domain from dir_control\n");
    }

    /* send a HUP signal to qmail-send process to reread control files */
    signal_process("qmail-send", SIGHUP);

    return (VA_NO_AUTH_CONNECTION);
  }	
 
  /* ask qmail to re-read it's new control files */
  if ( OptimizeAddDomain == 0 ) {
    signal_process("qmail-send", SIGHUP);
  }

  /* return back to the callers directory and return success */
  chdir(calling_dir);

  return(VA_SUCCESS);
}

/************************************************************************/

/* Delete a domain from the entire mail system
 *
 * If we have problems at any of the following steps, it has been 
 * decided that the best course of action is to continue rather than
 * abort. The idea behind this is to allow the removal of a partially
 * installed domain. We will emit warnings should any of the expected
 * cleanup steps fail.
 */
int vdeldomain( char *domain )
{
 struct stat statbuf;
 char Dir[MAX_BUFF];
 char domain_to_del[MAX_BUFF];
 char dircontrol[MAX_BUFF];
 uid_t uid;
 gid_t gid;

  /* we always convert domains to lower case */
  lowerit(domain);

  /* Check the length of the domain to del
   * If it exceeds the max storable size, 
   * then the user has made some sort of error in 
   * asking to del that domain, because such a domain
   * wouldnt be able to exist in the 1st place
   */
  if (strlen(domain) >= MAX_PW_DOMAIN) return (VA_DOMAIN_NAME_TOO_LONG);

  /* now we want to check a couple for things :
   * a) if the domain to del exists in the system
   * b) if the domain to del is an aliased domain or not
   */

  /* Take a backup of the domain we want to del,
   * because when we call vget_assign, if the domain
   * is an alias, then the domain parameter will be
   * rewritten on return as the name of the real domain
   */
  snprintf(domain_to_del, sizeof(domain_to_del), "%s", domain);

  /* check if the domain exists. If so extract the dir, uid, gid */
  if (vget_assign(domain, Dir, sizeof(Dir), &uid, &gid ) == NULL) {
    return(VA_DOMAIN_DOES_NOT_EXIST);
  }

  /* if this is an NOT aliased domain....
   * (aliased domains dont have any filestructure of their own)
   */
  if ( strcmp(domain_to_del, domain) == 0 ) {

    /* check if the domain's dir exists */
    if ( stat(Dir, &statbuf) != 0 ) {
      fprintf(stderr, "Warning: Could not access (%s)\n",Dir);
    }

    /*
     * Michael Bowe 23rd August 2003
     *
     * at this point, we need to write some code to check if any alias domains
     * point to this (real) domain. If we find such aliases, then I guess we
     * have a couple of options :
     * 1. Abort with an error, saying cant delete domain until all
     *    aliases are removed 1st (list them)
     * 2. Zap all the aliases in additon to this domain
     *
     */

    /* call the auth module to delete the domain from the storage */
    /* Note !! We must del domain from auth module __before__ we delete it from
     * fs, because deletion from auth module may fail !!!!
     */

    /* del a domain from the auth backend which includes :
     * - drop the domain's table, or del all users from users table
     * - delete domain's entries from lastauth table
     * - delete domain's limit's entries
     */
    if (vauth_deldomain(domain) != VA_SUCCESS ) {
      fprintf (stderr, "Warning: Failed while attempting to delete domain from auth backend\n");
    }

    /* vdel_limits does the following :
     * If we have mysql_limits enabled,
     *  it will delete the domain's entries from the limits table
     * Or if we arent using mysql_limits,
     *  it will delete the .qmail-admin file from the domain's dir
     *
     * Note there are inconsistencies in the auth backends.  Some
     * will run vdel_limits() in vauth_deldomain(), others don't.
     * For now, we always run it to be safe.  Ultimately, the auth
     * backends should to be updated to do this.
     */  
    vdel_limits(domain);

    /* delete the dir control info for this domain */
    if (vdel_dir_control(domain) != 0) {
      fprintf (stderr, "Warning: Failed to delete dir_control for %s\n", domain);
    }

    /* Now remove domain from filesystem */
    /* if it's a symbolic link just remove the link */
    if ( S_ISLNK(statbuf.st_mode) ) {
      if ( unlink(Dir) !=0) {
        fprintf (stderr, "Warning: Failed to remove symlink for %s\n", domain);
      }
    } else {
      char cwdbuff[MAX_BUFF];
      char *cwd;
      /* Not a symlink.. so we have to del some files structure now */
      /* zap the domain's directory tree */
      cwd = getcwd (cwdbuff, sizeof(cwdbuff));  /* save calling directory */
      if ( vdelfiles(Dir) != 0 ) {
        fprintf(stderr, "Warning: Failed to delete directory tree: %s\n", domain);
      }
      if (cwd != NULL) chdir (cwd);
    }

    /* decrement the master domain control info */
    snprintf(dircontrol, sizeof(dircontrol), "dom_%lu", (long unsigned)uid);
    dec_dir_control(dircontrol, uid, gid);
  }

  /* The following things need to happen for real and aliased domains */

  /* delete the email domain from the qmail control files :
   * rcpthosts, morercpthosts, virtualdomains
   */
  if (del_control(domain_to_del) != 0) {
    fprintf (stderr, "Warning: Failed to delete domain from qmail's control files\n");
  }

  /* delete the assign file line */
  if (del_domain_assign(domain_to_del, domain, Dir, uid, gid) != 0) {
    fprintf (stderr, "Warning: Failed to delete domain from the assign file\n");
  }

  /* send a HUP signal to qmail-send process to reread control files */
  signal_process("qmail-send", SIGHUP);

  return(VA_SUCCESS);

}

/************************************************************************/

/*
 * Add a virtual domain user
 */
int vadduser( char *username, char *domain, char *password, char *gecos, 
              int apop )
{
 char Dir[MAX_BUFF];
 char *user_hash;
 char calling_dir [MAX_BUFF];
 uid_t uid = VPOPMAILUID;
 gid_t gid = VPOPMAILGID;
 struct vlimits limits;
 char quota[50];

  /* check gecos for : characters - bad */
  if ( strchr(gecos,':')!=0) return(VA_BAD_CHAR);

  if ( strlen(username) >= MAX_PW_NAME ) return(VA_USER_NAME_TOO_LONG);
#ifdef USERS_BIG_DIR
  if ( strlen(username) == 1 ) return(VA_ILLEGAL_USERNAME);
#endif
  if ( strlen(domain) >= MAX_PW_DOMAIN ) return(VA_DOMAIN_NAME_TOO_LONG);
  if ( strlen(domain) < 3) return(VA_INVALID_DOMAIN_NAME);

  if ( strlen(password) >= MAX_PW_CLEAR_PASSWD ) return(VA_PASSWD_TOO_LONG);
  if ( strlen(gecos) >= MAX_PW_GECOS )    return(VA_GECOS_TOO_LONG);

  umask(VPOPMAIL_UMASK);
  lowerit(username);
  lowerit(domain);

  if ( is_username_valid(username) != 0 ) return(VA_ILLEGAL_USERNAME);
  if ( is_domain_valid(domain) != 0 ) return(VA_INVALID_DOMAIN_NAME);

  if ( vauth_getpw( username, domain ) != NULL ) return(VA_USERNAME_EXISTS);

  /* record the dir where the vadduser command was run from */
  getcwd(calling_dir, sizeof(calling_dir));

  /* lookup the home dir, uid and gid for the domain */
  if ( vget_assign(domain, Dir, sizeof(Dir), &uid, &gid)==NULL) {
    return(VA_DOMAIN_DOES_NOT_EXIST);
  }

  /* make sure we can load domain limits for default quota */
  if (vget_limits(domain, &limits) != 0) {
    return(VA_CANNOT_READ_LIMITS);
  }

  /* go to the domain's home dir (ie test it exists) */
  /* would a stat be a better option here? */
  if ( chdir(Dir) != 0 ) {
    return(VA_BAD_D_DIR);
  }

  /* create dir for the the user */ 
  if ( (user_hash=make_user_dir(username, domain, uid, gid)) == NULL ) {
    chdir(calling_dir);
    if (verrori != 0 ) return(verrori);
    else return(VA_BAD_U_DIR);
  }
        
  /* add the user to the auth backend */
  if (vauth_adduser(username, domain, password, gecos, user_hash, apop )!=0) {
    fprintf(stderr, "Failed while attempting to add user to auth backend\n");
    /* back out of changes made so far */
    chdir(Dir); if (strlen(user_hash)>0) { chdir(user_hash);} vdelfiles(username);
    chdir(calling_dir);
    return(VA_NO_AUTH_CONNECTION);
  }

  if (limits.defaultquota > 0) {
    if (limits.defaultmaxmsgcount > 0)
      snprintf (quota, sizeof(quota), "%dS,%dC", limits.defaultquota,
        limits.defaultmaxmsgcount);
    else
      snprintf (quota, sizeof(quota), "%dS", limits.defaultquota);
  } else {
    if (limits.defaultmaxmsgcount > 0)
      snprintf (quota, sizeof(quota), "%dC", limits.defaultmaxmsgcount);
    else
      strcpy (quota, "NOQUOTA");
  }
  vsetuserquota (username, domain, quota);

#ifdef SQWEBMAIL_PASS
  {
   /* create the sqwebmail-pass file in the user's maildir
    * This file contains a copy of the user's crypted password
    */
    struct vqpasswd *mypw;
    mypw = vauth_getpw( username, domain);
    if ( mypw != NULL ) { 
      vsqwebmail_pass( mypw->pw_dir, mypw->pw_passwd, uid, gid);
    }
  }
#endif

#ifdef ENABLE_AUTH_LOGGING
  if (vset_lastauth(username,domain,NULL_REMOTE_IP) !=0) {
    /* should we back out of all the work we have done so far? */
    chdir(calling_dir);
    fprintf (stderr, "Failed to create create lastauth entry\n");
    return (VA_NO_AUTH_CONNECTION);
  }
#endif

  /* jump back into the dir from which the vadduser was run */
  chdir(calling_dir);
  return(VA_SUCCESS);
}

/************************************************************************/

char randltr(void)
{
  static const char saltchar[] =
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  return saltchar[(rand() % 64)];
}

/************************************************************************/

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
 char salt[12];
 static int seeded = 0;

 if (!seeded) {
   seeded = 1;
   srand (time(NULL)^(getpid()<<15));
 }

#ifdef MD5_PASSWORDS
  salt[0] = '$';
  salt[1] = '1';
  salt[2] = '$';
  salt[3] = randltr();
  salt[4] = randltr();
  salt[5] = randltr();
  salt[6] = randltr();
  salt[7] = randltr();
  salt[8] = randltr();
  salt[9] = randltr();
  salt[10] = randltr();
  salt[11] = 0;
#else
  salt[0] = randltr();
  salt[1] = randltr();
  salt[2] = 0;
#endif

  tmpstr = crypt(clearpass,salt);
  if ( tmpstr == NULL ) return(VA_CRYPT_FAILED);

  strncpy(crypted,tmpstr, ssize);
  return(VA_SUCCESS);
}

/************************************************************************/

/* 
 * prompt the command line and get a password twice, that matches 
 */

char *vgetpasswd(char *user) 
{
 static char pass1[128];
 char pass2[128];
 char prompt[128];

 /* Michael Bowe 14th August 2003
  * Is setting up a static pass1 and returning a pointer
  * to it is the best way to run this function? Maybe there
  * is a better way we can do this....
  */

  memset(pass1, 0, sizeof(pass1));

  snprintf( prompt, sizeof(prompt), "Please enter password for %s: ", user);

  while( 1 ) {
    snprintf(pass1, sizeof(pass1), "%s", getpass(prompt));
    snprintf(pass2, sizeof(pass2), "%s", getpass("enter password again: "));

    if ( strcmp( pass1, pass2 ) != 0 ) {
      printf("Passwords do not match, try again\n");
    } else {
      break;
    }
  }
  return(pass1);
}

/************************************************************************/

/* 
 * vdelfiles : delete a directory tree
 *
 * input: directory to start the deletion
 * output: 
 *         0 on success
 *        -1 on failer
 */
int vdelfiles(char *dir)
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
    fprintf(stderr, "Failed to opendir()");
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
          fprintf (stderr, "Failed to delete directory %s", mydirent->d_name);
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
    fprintf(stderr, "Failed to cd to parent");
    return(-1);
  }

  /* delete the directory, I/O expensive */
  rmdir(dir);

  /* return success */
  return(0);
}

/************************************************************************/

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
 char tmpstr1[MAX_BUFF];
 char tmpstr2[MAX_BUFF];

  snprintf(tmpstr1, sizeof(tmpstr1), "%s/users/assign", QMAILDIR);

  /* stat assign file, if it's not there create one */
  if ( stat(tmpstr1,&mystat) != 0 ) {
    /* put a . on one line by itself */
    if ( (fs1 = fopen(tmpstr1, "w+"))==NULL ) {
      fprintf(stderr, "could not open assign file\n");
      return(-1);
    }
    fputs(".\n", fs1);
    fclose(fs1);
  }

  snprintf(tmpstr2, sizeof(tmpstr2), "+%s-:%s:%lu:%lu:%s:-::",
    alias_domain, real_domain, (long unsigned)uid, (long unsigned)gid, dir);

  /* update the file and add the above line and remove duplicates */
  if (update_file(tmpstr1, tmpstr2) !=0 ) {
   fprintf (stderr, "Failed while attempting to update_file() the assign file\n");
   return (-1);
  }

  /* set the mode in case we are running with a strange mask */
  chmod(tmpstr1, VPOPMAIL_QMAIL_MODE ); 

  /* compile the assign file */
  /* as of the 5.4 builds, we always need an updated assign file since
   * we call vget_assign to add the postmaster account.  The correct
   * solution is to cache the information somewhere so vget_assign
   * can pull from cache instead of having to read the assign file.
   */
  /* if ( OptimizeAddDomain == 0 ) */ update_newu();

  /* If we have more than 50 domains in rcpthosts
   * make a morercpthosts and compile it
   */
  if ( count_rcpthosts() >= 50 ) {
    snprintf(tmpstr1, sizeof(tmpstr1), "%s/control/morercpthosts", QMAILDIR);
    if (update_file(tmpstr1, alias_domain) !=0) {
      fprintf (stderr, "Failed while attempting to update_file() the morercpthosts file\n");
      return (-1);
    }
    snprintf(tmpstr1, sizeof(tmpstr1), "%s/control/morercpthosts", QMAILDIR);
    chmod(tmpstr1, VPOPMAIL_QMAIL_MODE ); 

    if ( OptimizeAddDomain == 0 ) compile_morercpthosts();

  /* or just add to rcpthosts */
  } else {
    snprintf(tmpstr1, sizeof(tmpstr1), "%s/control/rcpthosts", QMAILDIR);
    if (update_file(tmpstr1, alias_domain) != 0) {
      fprintf (stderr, "Failed while attempting to update_file() the rcpthosts file\n");
      return (-1);
    }
    snprintf(tmpstr1, sizeof(tmpstr1), "%s/control/rcpthosts", QMAILDIR);
    chmod(tmpstr1, VPOPMAIL_QMAIL_MODE ); 
  }
    
  /* Add to virtualdomains file and remove duplicates  and set mode */
  snprintf(tmpstr1, sizeof(tmpstr1), "%s/control/virtualdomains", QMAILDIR );
  snprintf(tmpstr2, sizeof(tmpstr2), "%s:%s", alias_domain, alias_domain );
  if (update_file(tmpstr1, tmpstr2) !=0 ) {
    fprintf (stderr, "Failed while attempting to update_file() the virtualdomains file\n");
    return (-1);
  };
  chmod(tmpstr1, VPOPMAIL_QMAIL_MODE ); 

  /* make sure it's not in locals and set mode */
  snprintf(tmpstr1, sizeof(tmpstr1), "%s/control/locals", QMAILDIR);
  if (remove_line( alias_domain, tmpstr1) < 0) {
    fprintf (stderr, "Failure while attempting to remove_line() the locals file\n");
    return(-1);
  }
  chmod(tmpstr1, VPOPMAIL_QMAIL_MODE ); 

  return(0);
}

/************************************************************************/

/*
 * delete a domain from the control files
 * the control files consist of :
 * - /var/qmail/control/rcpthosts
 * - /var/qmail/control/virtualdomains
 */
int del_control(char *domain ) 
{
 char tmpbuf1[MAX_BUFF];
 char tmpbuf2[MAX_BUFF];
 struct stat statbuf;

 int problem_occurred = 0;

  /* delete entry from control/rcpthosts (if it is found) */
  snprintf(tmpbuf1, sizeof(tmpbuf1), "%s/control/rcpthosts", QMAILDIR);
  switch ( remove_line( domain, tmpbuf1) ) {

    case -1 :
      /* error ocurred in remove line */
      fprintf (stderr, "Failed while attempting to remove_line() the rcpthosts file\n");
      problem_occurred = 1;
      break;

    case 0 :
      /* not found in rcpthosts, so try morercpthosts */
      snprintf(tmpbuf1, sizeof(tmpbuf1), "%s/control/morercpthosts", QMAILDIR);
  
      switch (remove_line( domain, tmpbuf1) ) {

        case -1 :
          /* error ocurred in remove line
           * but this is normal enough as on smaller servers, the morercpthosts
           * file wont exist. So ignore this 'error' condition.
           */
          break; 

        case 0 :
         /* not found in morercpthosts */
          break;

        case 1 :
          /* was removed from morercpthosts */
          /* now test to see if morercpthosts exists */
          if ( stat( tmpbuf1, &statbuf) == 0 ) {
            /* morercpthosts exists. Now check to see if its empty */
            if ( statbuf.st_size == 0 ) {
              /* is empty. So delete it */
              unlink(tmpbuf1);
              /* also delete the morercpthosts.cdb */
              strncat(tmpbuf1, ".cdb", sizeof(tmpbuf1)-strlen(tmpbuf1)-1);
              unlink(tmpbuf1);
            } else {
              /* morercpthosts is not empty, so compile it */
              compile_morercpthosts();
              /* make sure correct permissions are set on morercpthosts */
              chmod(tmpbuf1, VPOPMAIL_QMAIL_MODE ); 
            }
          }
          break; 

      } /* switch for morercpthosts */ 
      break;

    case 1 : /* we removed the line successfully */
      /* make sure correct permissions are set on rcpthosts */
      chmod(tmpbuf1, VPOPMAIL_QMAIL_MODE );
      break; 
  } /* switch for rcpthosts */

  /* delete entry from control/virtualdomains (if it exists) */
  snprintf(tmpbuf1, sizeof(tmpbuf1), "%s:%s", domain, domain);
  snprintf(tmpbuf2, sizeof(tmpbuf2), "%s/control/virtualdomains", QMAILDIR);
  if (remove_line( tmpbuf1, tmpbuf2) < 0 ) {
    fprintf(stderr, "Failed while attempting to remove_line() the virtualdomains file\n"); 
    problem_occurred = 1; 
  }

  /* make sure correct permissions are set on virtualdomains */
  chmod(tmpbuf2, VPOPMAIL_QMAIL_MODE ); 
  
  if (problem_occurred == 1) {
    return (-1);
  } else { 
    return(0);
  }
}

/************************************************************************/

/*
 * delete a domain from the users/assign file
 * input : lots ;)
 * output : 0 = success
 *          less than error = failure
 *
 */
int del_domain_assign( char *alias_domain, char *real_domain, 
                       char *dir, gid_t uid, gid_t gid )  
{
 char search_string[MAX_BUFF];
 char assign_file[MAX_BUFF];

  /* format the removal string */ 
  snprintf(search_string, sizeof(search_string), "+%s-:%s:%lu:%lu:%s:-::",
    alias_domain, real_domain, (long unsigned)uid, (long unsigned)gid, dir);

  /* format the assign file name */
  snprintf(assign_file, sizeof(assign_file), "%s/users/assign", QMAILDIR);

  /* remove the formatted string from the file */
  if (remove_line( search_string, assign_file) < 0) {
    fprintf(stderr, "Failed while attempting to remove_line the assign file\n");
    return (-1);
  }

  /* force the permission on the file */
  chmod(assign_file, VPOPMAIL_QMAIL_MODE ); 

  /* compile assign file */
  update_newu();

  return(0);
}

/************************************************************************/

/*
 * Generic remove a line from a file utility
 * input: template to search for
 *        file to search inside
 *
 * output: -1 on failure
 *          0 on success, no match found
 *          1 on success, match was found
 */
int remove_line( char *template, char *filename )
{
 char tmpbuf1[MAX_BUFF];
 struct stat statbuf;
 FILE *fs_orig;
 FILE *fs_bak;
#ifdef FILE_LOCKING
 FILE *fs_lock;
#endif
 int found;
 int i;

  /* if we can't stat the file, return error */
  if ( stat(filename,&statbuf) == -1 ) return(-1);

#ifdef FILE_LOCKING
  /* format the lock file name */
  snprintf(tmpbuf1, sizeof(tmpbuf1), "%s.lock", filename);

  /* open the file with write permissions and check for error */
  if ( (fs_lock = fopen(tmpbuf1, "w+")) == NULL ) {
    /* return error */
    fprintf(stderr, "could not open lock file %s\n", tmpbuf1);
    return(-1);
  }

  /* ask for a write lock on the file
   * we don't want anyone writing to it now 
   */
  if ( get_write_lock(fs_lock) < 0 ) {

    /* remove lock */
    unlock_lock(fileno(fs_lock), 0, SEEK_SET, 0);
    fclose(fs_lock);

    /* print error message */
    fprintf(stderr, "could not get write lock on %s\n", tmpbuf1);

    /* return error */
    return(-1);
  }
#endif

  /* format a backup file name */
  snprintf(tmpbuf1, sizeof(tmpbuf1), "%s.bak", filename);

  /* remove the file if it exists already */
  unlink(tmpbuf1);

  /* move the orignal file to the .bak file */
  rename(filename, tmpbuf1);

  /* open the file and check for error */
  if ( (fs_orig = fopen(filename, "w+")) == NULL ) {

#ifdef FILE_LOCKING
    /* release resources */
    fclose(fs_lock);
#endif

    fprintf(stderr, "%s file would not open w+\n", filename);
    return(-1);
  }

  /* open the .bak file in read mode and check for error */

/* Michael Bowe 23rd August 2003
 * Isnt the w+ bit of this code wrong?
 * At this point our orignal file is known as .bak
 * so why would we want to try and w+ it? Wont this
 * del the contents of the file? Ouch!
 * I have remarked the original code out and left my version below
 *
 *  if ( (fs_bak = fopen(tmpbuf1, "r+")) == NULL ) {
 *   if ( (fs_bak = fopen(tmpbuf1, "w+")) == NULL ) {
 *     fprintf(stderr, "%s would not open r+ or w+\n", tmpbuf1);
 *     fclose(fs_orig);
 * #ifdef FILE_LOCKING
 *     unlock_lock(fileno(fs_lock), 0, SEEK_SET, 0);
 *     fclose(fs_lock);
 * #endif
 *      return(-1);
 *    }
 *  }
 */

  if ( (fs_bak = fopen(tmpbuf1, "r+")) == NULL ) {
     fprintf(stderr, "%s would not open r+ \n", tmpbuf1);
     fclose(fs_orig);
#ifdef FILE_LOCKING
     unlock_lock(fileno(fs_lock), 0, SEEK_SET, 0);
     fclose(fs_lock);
#endif
     return(-1);
  }

  /* Search the .bak file line by line.
   * Copy across any lines that do not contain our search string
   * back to the original filename.
   */
  found = 0;
  /* suck in a line from the .bak file */
  while (fgets(tmpbuf1,sizeof(tmpbuf1),fs_bak)!=NULL){
    /* if a newline was sucked in (likely), change it to be a \0 */
    for(i=0;tmpbuf1[i]!=0;++i) if (tmpbuf1[i]=='\n') tmpbuf1[i]=0;
    /* look to see if this line contains our search string */ 
    if ( strcmp(template, tmpbuf1) != 0) {
      /* match not found, so copy this line from the .bak to the filename */
      fputs(tmpbuf1, fs_orig);
      fputs("\n", fs_orig);
    } else {
      found = 1;
    }
  }

  /* we are done with these two, release the resources */
  fclose(fs_orig);
  fclose(fs_bak);

  /* format the name of the backup file */
  snprintf(tmpbuf1, sizeof(tmpbuf1), "%s.bak", filename);
  /* remove the .bak file */
  unlink(tmpbuf1);

#ifdef FILE_LOCKING
  /* unlock, we are done */
  unlock_lock(fileno(fs_lock), 0, SEEK_SET, 0);

  /* close the lock file to release resources */
  fclose(fs_lock);
#endif

  /* return 0 = everything went okay, but we didn't find it
   *        1 = everything went okay, and we found a match
   */
  return(found);

}

/************************************************************************/

/* 
 * Recursive change ownership utility 
 */
int r_chown(char *path, uid_t owner, gid_t group )
{
 DIR *mydir;
 struct dirent *mydirent;
 struct stat statbuf;

  chown(path,owner,group);
  if (chdir(path) == -1) {
    fprintf(stderr, "r_chown() : Failed to cd to directory %s", path);
    return(-1);
  }
  mydir = opendir(".");
  if ( mydir == NULL ) { 
    fprintf(stderr, "r_chown() : Failed to opendir()");
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
  closedir(mydir);
  if (chdir("..") == -1) {
    fprintf(stderr, "rchown() : Failed to cd to parent");
    return(-1);
  }
  return(0);
}

/************************************************************************/

/* 
 * Send a signal to a process utility function
 *
 * name    = name of process
 * sig_num = signal number 
 */
int signal_process(char *name, int sig_num)
{
 FILE *ps;
 char *tmpstr;
 int  col;
 pid_t tmppid;
 pid_t mypid;
 int  pid_col=0;
 char pid[MAX_BUFF];
 char tmpbuf1[MAX_BUFF];

  mypid = getpid();

  if ( (ps = popen(PS_COMMAND, "r")) == NULL ) {
    perror("popen on ps command");
    return(-1);
  }

  if (fgets(tmpbuf1, sizeof(tmpbuf1), ps)!= NULL ) {
    col=0;
    tmpstr = strtok(tmpbuf1, PS_TOKENS);
    while (tmpstr != NULL ) {
      if (strcmp(tmpstr, "PID") == 0 ) pid_col = col;

      tmpstr = strtok(NULL, PS_TOKENS);
      ++col;
    }
  }

  while (fgets(tmpbuf1, sizeof(tmpbuf1), ps)!= NULL ) {
    if ( strstr( tmpbuf1, name ) != NULL && 
         strstr(tmpbuf1,"supervise")==NULL) {
      tmpstr = strtok(tmpbuf1, PS_TOKENS);
      col = 0;
      do {
        if( col == pid_col ) {
          snprintf(pid, sizeof(pid), "%s", tmpstr);
          break;
        } 
        ++col;
        tmpstr = strtok(NULL, PS_TOKENS);
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

/************************************************************************/

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

/************************************************************************/

/*
 * parse out user and domain from an email address utility function
 * 
 * email  = input email address
 * user   = parsed user
 * domain = parsed domain
 * buff_size = the size of the user and domain buffer. 
 *             These need to be the same size or potential buffer overflows
 *             could occur!
 * 
 * return 0 on success
 *       -1 on error
 */
int parse_email(char *email, char *user, char *domain, int buff_size ) 
{
 int i;
 int n;
 int len;
 char *at = NULL;

  lowerit(email);

  len = strlen(ATCHARS);
  for(i=0;i<len; ++i ) if ((at=strchr(email,ATCHARS[i]))) break;

  /* did we find an "AT" char in the email address? */
  if ( at!=NULL ) {
    /* yep we found an AT char */
    /* work out what pos it is in the email address array, store this in n */
    n = at - email + 1;
    if ( n > buff_size ) n = buff_size;
    /* suck out the username */
    snprintf(user, n, "%s", email); 
    /* now suck out the domain name */
    snprintf(domain, buff_size, "%s", ++at);
  } else {
    /* No AT char found, so populate username, leave domain blank */
    snprintf(user, buff_size, "%s", email);
    domain[0] = 0;
  }

  /* check the username for any invalid chars */
  if ( is_username_valid( user ) != 0 ) {
    fprintf(stderr, "user invalid %s\n", user);
    return(-1);
  }

  /* check the domain for any invalid chars */
  if ( is_domain_valid( domain ) != 0 ) {
    fprintf(stderr, "domain invalid %s\n", domain);
    return(-1);
  }

  /* if we havent found a domain, try and set it to the the default domain */
  vset_default_domain(domain);

  return(0);
} 

/************************************************************************/

/*
 * update a users virtual password file entry with a different password
 */
int vpasswd( char *username, char *domain, char *password, int apop )
{
 struct vqpasswd *mypw;
 char Crypted[MAX_BUFF];
#ifdef SQWEBMAIL_PASS
 uid_t uid;
 gid_t gid;
#endif

  if ( strlen(username) >= MAX_PW_NAME ) return(VA_USER_NAME_TOO_LONG);
#ifdef USERS_BIG_DIR  
  if ( strlen(username) == 1 ) return(VA_ILLEGAL_USERNAME);
#endif
  if ( strlen(domain) >= MAX_PW_DOMAIN ) return(VA_DOMAIN_NAME_TOO_LONG);
  if ( strlen(password) >= MAX_PW_CLEAR_PASSWD ) return(VA_PASSWD_TOO_LONG);

  lowerit(username);
  lowerit(domain);

  /* get the password entry for this user */
  mypw = vauth_getpw( username, domain);
  if ( mypw == NULL ) return(-1); 

  /* dont update password, if password updates are disabled */
  if ( mypw->pw_flags & NO_PASSWD_CHNG ) return(-1);

  /* encrypt their supplied password, and save it */
  mkpasswd3(password,Crypted, sizeof(Crypted));
  mypw->pw_passwd = Crypted;

#ifdef CLEAR_PASS
  /* save the clear password too (if clear passwords are enabled) */
  mypw->pw_clear_passwd = password;
#endif

#ifdef SQWEBMAIL_PASS
  /* update the sqwebmail-pass file in the user's maildir (if required) */
  vget_assign(domain, NULL, 0, &uid, &gid );
  vsqwebmail_pass( mypw->pw_dir, Crypted, uid, gid);
#endif
  return (vauth_setpw( mypw, domain));
}

/************************************************************************/

/*
 * delete a user from a virtual domain password file
 */
int vdeluser( char *user, char *domain )
{
 struct vqpasswd *mypw;
 char Dir[MAX_BUFF];
 uid_t uid;
 gid_t gid;
 char calling_dir[MAX_BUFF];

  if ( user == 0 || strlen(user)<=0) return(VA_ILLEGAL_USERNAME);

  /* Michael Bowe 23rd August 2003 
   * should we do a vset_default_domain(domain) here?
   * This function is called by vdeluser.c which will ensure
   * domain is set. But what if this function is called from
   * somewhere else and is passed with a null domain?
   * Should we display en error (which is what will happen when
   * vget_assign runs below.
   */

  umask(VPOPMAIL_UMASK);

  lowerit(user);
  lowerit(domain);

  /* see if the user exists in the authentication system */
  if ((mypw = vauth_getpw(user, domain)) == NULL) { 
    return(VA_USER_DOES_NOT_EXIST);
  }

  /* backup the dir where the vdeluser was run from */
  getcwd(calling_dir, sizeof(calling_dir));

  /* lookup the location of this domain's directory */
  if ( vget_assign(domain, Dir, sizeof(Dir), &uid, &gid ) ==NULL ) {
    return(VA_DOMAIN_DOES_NOT_EXIST);
  }

  /* change into that directory */
  if ( chdir(Dir) != 0 ) {
    chdir(calling_dir);
    return(VA_BAD_D_DIR);
  }

  /* del the user from the auth system */
  if (vauth_deluser( user, domain ) !=0 ) {
    fprintf (stderr, "Failed to delete user from auth backend\n");
    chdir(calling_dir);
    return (-1);
  }

  dec_dir_control(domain, uid, gid);

  /* remove the user's directory from the file system 
   * and check for error
   */
  if ( vdelfiles(mypw->pw_dir) != 0 ) {
    fprintf(stderr, "could not remove %s\n", mypw->pw_dir);
    chdir(calling_dir);
    return(VA_BAD_DIR);
  }

  /* go back to the callers directory */
  chdir(calling_dir);
  return(VA_SUCCESS);

}

/************************************************************************/

/*
 * make all characters in a string be lower case
 */
void lowerit(char *instr )
{
 int size;

  if (instr==NULL) return;
  for(size=0;*instr!=0;++instr,++size ) {
    if (isupper((int)*instr)) *instr = tolower(*instr);
    
    /* Michael Bowe 23rd August 2003
     * this looks like a bit of a kludge...
     * how can we improve on it?
     */

    /* add alittle size protection */
    if ( size == 156 ) {
      *instr = 0;
      return;
    }
  } 
}

/************************************************************************/

int update_file(char *filename, char *update_line)
{
 FILE *fs = NULL;
 FILE *fs1 = NULL;
#ifdef FILE_LOCKING
 FILE *fs3 = NULL;
#endif
 char tmpbuf1[MAX_BUFF];
 char tmpbuf2[MAX_BUFF];
 int user_assign = 0;
 int i;

#ifdef FILE_LOCKING
  snprintf(tmpbuf1, sizeof(tmpbuf1), "%s.lock", filename);
  if ( (fs3 = fopen(tmpbuf1, "w+")) == NULL ) {
    fprintf(stderr, "could not open lock file %s\n", tmpbuf1);
    return(VA_COULD_NOT_UPDATE_FILE);
  }

  if ( get_write_lock(fs3) < 0 ) return(-1);
#endif

  snprintf(tmpbuf1, sizeof(tmpbuf1), "%s.%lu", filename, (long unsigned)getpid());
  fs1 = fopen(tmpbuf1, "w+");
  if ( fs1 == NULL ) {
#ifdef FILE_LOCKING
    unlock_lock(fileno(fs3), 0, SEEK_SET, 0);
    fclose(fs3);
    return(VA_COULD_NOT_UPDATE_FILE);
#endif
  }

  snprintf(tmpbuf1, sizeof(tmpbuf1), "%s", filename);
  if ( (fs = fopen(tmpbuf1, "r+")) == NULL ) {
    if ( (fs = fopen(tmpbuf1, "w+")) == NULL ) {
      fclose(fs1);
#ifdef FILE_LOCKING
      fclose(fs3);
      unlock_lock(fileno(fs3), 0, SEEK_SET, 0);
#endif
      return(VA_COULD_NOT_UPDATE_FILE);
    }
  }

  while( fgets(tmpbuf1,sizeof(tmpbuf1),fs) != NULL ) {
    snprintf(tmpbuf2, sizeof(tmpbuf2), "%s", tmpbuf1);
    for(i=0;tmpbuf1[i]!=0;++i) {
      if (tmpbuf1[i]=='\n') {
        tmpbuf1[i]=0;
      }
    }

    /* special case for users/assign */
    if ( strncmp(tmpbuf1, ".", sizeof(tmpbuf1)) == 0 ) {
      fprintf(fs1, "%s\n", update_line);
      user_assign = 1;
    } else if ( strncmp(tmpbuf1, update_line, sizeof(tmpbuf1)) != 0 ) {
      fputs(tmpbuf2, fs1);
      }
  }

  if ( user_assign == 1 ) fprintf(fs1, ".\n");
  else fprintf(fs1, "%s\n", update_line);

  fclose(fs);
  fclose(fs1);

  snprintf(tmpbuf1, sizeof(tmpbuf1), "%s", filename);
  snprintf(tmpbuf2, sizeof(tmpbuf2), "%s.%lu", filename, (long unsigned)getpid());

  rename(tmpbuf2, tmpbuf1);

#ifdef FILE_LOCKING
  unlock_lock(fileno(fs3), 0, SEEK_SET, 0);
  fclose(fs3);
#endif

  return(0);
}

/************************************************************************/

/*
 * Update a users quota
 */
int vsetuserquota( char *username, char *domain, char *quota )
{
 struct vqpasswd *mypw;
 char *formattedquota;
 int ret;

  if ( strlen(username) >= MAX_PW_NAME ) return(VA_USER_NAME_TOO_LONG);
#ifdef USERS_BIG_DIR  
  if ( strlen(username) == 1 ) return(VA_ILLEGAL_USERNAME);
#endif  
  if ( strlen(domain) >= MAX_PW_DOMAIN ) return(VA_DOMAIN_NAME_TOO_LONG);
  if ( strlen(quota) >= MAX_PW_QUOTA )    return(VA_QUOTA_TOO_LONG);

  lowerit(username);
  lowerit(domain);

  /* correctly format the quota string,
   * and then store the quota into the auth backend
   */
  formattedquota = format_maildirquota(quota);
  ret = vauth_setquota( username, domain, formattedquota);
  if (ret != VA_SUCCESS ) return(ret);

  mypw = vauth_getpw( username, domain );
  remove_maildirsize(mypw->pw_dir);
  if (strcmp (quota, "NOQUOTA") != 0) {
   uid_t uid;
   gid_t gid;
   char maildir[MAX_BUFF];
    snprintf(maildir, sizeof(maildir), "%s/Maildir/", mypw->pw_dir);
    umask(VPOPMAIL_UMASK);
    (void)vmaildir_readquota(maildir, formattedquota);
    if ( vget_assign(domain, NULL, 0, &uid, &gid)!=NULL) {
      strcat(maildir, "maildirsize");
      chown(maildir,uid,gid);
    }
  }
  return(0);
}

/************************************************************************/

/*
 * count the lines in /var/qmail/control/rcpthosts
 */
int count_rcpthosts()
{
 char tmpstr1[MAX_BUFF];
 FILE *fs;
 int count;

  snprintf(tmpstr1, sizeof(tmpstr1), "%s/control/rcpthosts", QMAILDIR);
  fs = fopen(tmpstr1, "r");
  if ( fs == NULL ) return(0);

  count = 0;
  while( fgets(tmpstr1, sizeof(tmpstr1), fs) != NULL ) ++count;

  fclose(fs);
  return(count);

}

/************************************************************************/

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

/************************************************************************/

/*
 * fill out a passwd structure from then next
 * line in a file 
 */ 
struct vqpasswd *vgetent(FILE *pw)
{
    static struct vqpasswd pwent;
    static char line[MAX_BUFF];
    int i=0,j=0;
    char *tmpstr;
    char *tmpstr1;

    if (fgets(line,sizeof(line),pw) == NULL) return NULL;

    for (i=0; line[i] != 0; i++) if (line[i] == ':') j++;
    if (j < 6) return NULL;

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
    if (*tmpstr) { *tmpstr = 0; ++tmpstr; }

    pwent.pw_shell  = tmpstr; 
    while (*tmpstr!=0 && *tmpstr!=':' && *tmpstr!='\n') ++tmpstr;
    if (*tmpstr) { *tmpstr = 0; ++tmpstr; }

#ifdef CLEAR_PASS
    pwent.pw_clear_passwd  = tmpstr; 
    while (*tmpstr!=0 && *tmpstr!='\n') ++tmpstr;
    if (*tmpstr) { *tmpstr = 0; ++tmpstr; }
#endif

    return &pwent;
}

/************************************************************************/

/*
 * figure out where to put the user and
 * make the directories if needed
 *
 * if successfull, return a pointer to the user hash
 * on error return NULL
 */
char *make_user_dir(char *username, char *domain, uid_t uid, gid_t gid)
{
 char *user_hash;
 struct vqpasswd *mypw;
 char calling_dir[MAX_BUFF];
 char domain_dir[MAX_BUFF];
 const char *dirnames[] = {"Maildir", "Maildir/new", "Maildir/cur", 
	"Maildir/tmp"};
 int i;

  verrori = 0;
  /* record the dir where the command was run from */
  getcwd(calling_dir, sizeof(calling_dir));

  /* retrieve the dir that stores this domain */
  if (vget_assign(domain, domain_dir, sizeof(domain_dir), NULL, NULL) == NULL) {
    fprintf(stderr, "Error. vget_assign() failed for domain : %s",domain); 
    return(NULL);
  }

  /* go to the dir for our chosen domain */
  chdir(domain_dir); 

  user_hash="";
#ifdef USERS_BIG_DIR
  /* go into a user hash dir if required */
  open_big_dir(domain, uid, gid);
  user_hash = next_big_dir(uid, gid);
  close_big_dir(domain, uid, gid);
  chdir(user_hash);
#endif
  /* check the length of the dir path to make sure it is not too 
     long to save back to the auth backend */
  if ((strlen(domain_dir)+strlen(user_hash)+strlen(username)) >= MAX_PW_DIR) {
    fprintf (stderr, "Error. Path exceeds maximum permitted length\n");
    chdir(calling_dir);
    return (NULL);
  }

  /* create the users dir, including all the Maildir structure */ 
  if ( mkdir(username, VPOPMAIL_DIR_MODE) != 0 ) {
    /* need to add some code to remove the hashed dirs we created above... */
    verrori = VA_EXIST_U_DIR;
    chdir(calling_dir);
    return(NULL);
  }

  if ( chdir(username) != 0 ) {
    /* back out of changes made above */
    chdir(domain_dir); chdir(user_hash); vdelfiles(username);
    chdir(calling_dir);
    fprintf(stderr, "make_user_dir: error 2\n");
    return(NULL);
  }

  for (i = 0; i < sizeof(dirnames)/sizeof(dirnames[0]); i++) {
    if (mkdir(dirnames[i],VPOPMAIL_DIR_MODE) == -1){ 
      fprintf(stderr, "make_user_dir: failed on %s\n", dirnames[i]);
      /* back out of changes made above */
      chdir("..");
      vdelfiles(username);
      chdir(calling_dir);
      return(NULL);
    }
  }

  /* set permissions on the user's dir */
  r_chown(".", uid, gid);

  /* see if the user already exists in the auth backend */
  mypw = vauth_getpw( username, domain);
  if ( mypw != NULL ) { 

    /* user does exist in the auth backend, so fill in the dir field */
    mypw->pw_dir = malloc(MAX_PW_DIR);
    if ( strlen(user_hash) > 0 ) {
      snprintf(mypw->pw_dir, MAX_PW_DIR, "%s/%s/%s", domain_dir, user_hash, username);
    } else {
      snprintf(mypw->pw_dir, MAX_PW_DIR, "%s/%s", domain_dir, username);
    }
    /* save these values to the auth backend */
    vauth_setpw( mypw, domain );

#ifdef SQWEBMAIL_PASS
    vsqwebmail_pass( mypw->pw_dir, mypw->pw_passwd, uid, gid);
#endif
    free (mypw->pw_dir);
  }

  chdir(calling_dir);
  return(user_hash);
}

/************************************************************************/

int r_mkdir(char *path, uid_t uid, gid_t gid )
{
 char tmpbuf[MAX_BUFF];
 int i;

  for(i=0;path[i]!=0;++i){
    if ( (i > 0) && (path[i] == '/') ) {
      tmpbuf[i] = 0;
      if (mkdir(tmpbuf,VPOPMAIL_DIR_MODE) == 0)
        chown(tmpbuf, uid, gid);
    }
    tmpbuf[i] = path[i];
  }
  mkdir(path,VPOPMAIL_DIR_MODE);
  chown(path, uid, gid);
  return(0);
}

/************************************************************************/

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

/************************************************************************/

/* Function used by qmailadmin to auth users */

struct vqpasswd *vauth_user(char *user, char *domain, char* password, char *apop)
 {
  struct vqpasswd *mypw;
  char *tmpstr;
  uid_t uid;
  gid_t gid;
 
   if ( password == NULL ) return(NULL);
   mypw = vauth_getpw(user, domain);
   if ( mypw == NULL ) return(NULL);
   if ( vauth_crypt(user, domain, password, mypw) != 0 ) return(NULL);
 
   tmpstr = vget_assign(domain, NULL, 0, &uid, &gid );
   mypw->pw_uid = uid;
   mypw->pw_gid = gid;
   return(mypw);
 }

/************************************************************************/

/*
 * default_domain()
 *   returns a pointer to a string, containing
 *   the default domain (or blank if not set).  Loads from
 *   ~vpopmail/etc/defaultdomain.  Only loads once per program
 *   execution.
 */
char *default_domain()
{
   static int init = 0;
   static char d[MAX_PW_DOMAIN];
   char path[MAX_BUFF];
   int dlen;
   FILE *fs;

   if (!init) {
     init++;
     d[0] = '\0';  /* make sure d is empty in case file doesn't exist */
     snprintf (path, sizeof(path), "%s/etc/defaultdomain", VPOPMAILDIR);

     fs = fopen (path, "r");
     if (fs != NULL) {
       fgets (d, sizeof(d), fs);
       fclose (fs);
       dlen = strlen(d) - 1;
       if (d[dlen] == '\n') { d[dlen] = '\0'; }
     }
   }
   return d;
} 

/************************************************************************/

/*
 * If domain is blank, set it to the VPOPMAIL_DOMAIN environment
 * variable, an ip alias domain, or the default domain.
 */
void vset_default_domain( char *domain ) 
{
 char *tmpstr, *cp;
#ifdef IP_ALIAS_DOMAINS
 char host[MAX_BUFF];
#endif

  if (domain != NULL) {
    if (strlen(domain)>0) {
      /* domain isnt blank, so dont try to set it */
      return;
    }
  }

  /* domain is blank, so now try various lookups to set it */

  tmpstr = getenv("VPOPMAIL_DOMAIN");
  if ( tmpstr != NULL) {

    /* As a security precaution, remove all but good chars */
    for (cp = tmpstr; *(cp += strspn(cp, ok_env_chars)); /* */) {*cp='_';}

    /* Michael Bowe 14th August 2003
     * How can we prevent possible buffer overflows here
     * For the moment, stick with a conservative size of MAX_PW_DOMAIN
     */
    snprintf(domain, MAX_PW_DOMAIN, "%s", tmpstr);
    return;
  }

#ifdef IP_ALIAS_DOMAINS
  tmpstr = getenv("TCPLOCALIP");

  /* courier-imap uses IPv6 */
  if ( tmpstr != NULL ) {

    /* As a security precaution, remove all but good chars */
    for (cp = tmpstr; *(cp += strspn(cp, ok_env_chars)); ) {*cp='_';}

    /* Michael Bowe 14th August 2003
     * Mmmm Yuk below. What if TCPLOCALIP=":\0"
     * Buffer overflow.
     * Need to perhaps at least check strlen of tmpstr
     */
    if ( tmpstr[0] == ':') {
      tmpstr +=2;
      while(*tmpstr!=':') ++tmpstr;
      ++tmpstr;
    }
  }

  memset(host,0,sizeof(host));
  /* take the ip address that the connection was made to
   * and go and look this up in our vip map
   * and then store the domain into the host var 
   */
  if ( vget_ip_map(tmpstr,host,sizeof(host))==0 && !host_in_locals(host)){
    if ( strlen(host) > 0 ) {
      /* Michael Bowe 14th August 2003
       * How can we prevent possible buffer overflows here
       * For the moment, stick with a conservative size of MAX_PW_DOMAIN
       */
      snprintf(domain, MAX_PW_DOMAIN, "%s", host);
    }
    return;
  }
#endif /* IP_ALIAS_DOMAINS */

  /* Michael Bowe 14th August 2003
   * How can we prevent possible buffer overflows here
   * For the moment, stick with a conservative size of MAX_PW_DOMAIN
   */
  snprintf(domain, MAX_PW_DOMAIN, "%s", DEFAULT_DOMAIN);
}

/************************************************************************/

#ifdef IP_ALIAS_DOMAINS
/* look to see if the nominated domain is is locals file
 * return 1 if there is a match
 * return 0 if there is no match
 */
int host_in_locals(char *domain)
{
 int i;
 char tmpbuf[MAX_BUFF];
 FILE *fs;

  snprintf(tmpbuf, sizeof(tmpbuf), "%s/control/locals", QMAILDIR);
  if ((fs = fopen(tmpbuf,"r")) == NULL) {
    return(0);
  }

  while( fgets(tmpbuf,sizeof(tmpbuf),fs) != NULL ) {
    /* usually any newlines into nulls */
    for(i=0;tmpbuf[i]!=0;++i) if (tmpbuf[i]=='\n') tmpbuf[i]=0;
    /* Michael Bowe 14th August 2003
     * What happens if domain isnt null terminated?
     */
    if (( strcmp( domain, tmpbuf)) == 0 ) {
      /* we found a match */
      fclose(fs);
      return(1);
    }

    /* always match with localhost */
    if ( strcmp(domain, "localhost") == 0 && 
       strstr(domain,"localhost") != NULL ) {
      fclose(fs);
      return(1);
    }
  }

  fclose(fs);
  return(0);
}
#endif

/************************************************************************/

/* Convert error flag to text */
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
   case VA_PARSE_ERROR:
    return("error parsing data");
   case VA_CANNOT_READ_LIMITS:
    return("can't read domain limits");
   default:
    return("Unknown error");
  }
}

/************************************************************************/

/* Michael Bowe 21st Aug 2003
 * This function doesnt appear to be used by vpopmail or qmailadmin 
 * Consider it for removal perhaps
 */
/* Add an entry to a domain/.qmail-alias file */
int vadddotqmail( char *alias, char *domain,... ) 
{
 struct vqpasswd *mypw = NULL; 
 FILE *fs;
 va_list args;
 char *email;
 char Dir[MAX_BUFF];
 uid_t uid;
 gid_t gid;
 char tmpbuf[MAX_BUFF];

  /* extract the details for the domain (Dir, uid, gid) */
  if ( vget_assign(domain, Dir, sizeof(Dir), &uid, &gid ) == NULL) {
    return(VA_DOMAIN_DOES_NOT_EXIST);
  }

  /* open the .qmail-alias file for writing */
  snprintf(tmpbuf, sizeof(tmpbuf), "%s/.qmail-%s", Dir, alias);
  if ((fs=fopen(tmpbuf, "w")) == NULL) return(VA_COULD_NOT_OPEN_DOT_QMAIL);

  va_start(args,domain);
  while ( (email=va_arg(args, char *)) != NULL ) {
    /* are we dealing with an email address? */
    if ( strstr(email, "@") == NULL ) {
      /* not an email address */
      /* get passwd entry for this user */
      mypw = vauth_getpw( email, domain );
      if ( mypw == NULL ) return(VA_USER_DOES_NOT_EXIST);
      /* write out the appropriate maildir entry for this user */
      fprintf(fs, "%s/Maildir/\n", mypw->pw_dir);
    } else {
      /* yes, we have an email address, so write it out */
      fprintf(fs, "%s\n", email);
    }
  }
  fclose(fs);

  /* setup the permission of the .qmail-alias file */
  snprintf(tmpbuf, sizeof(tmpbuf), "%s/.qmail-%s", Dir, alias);
  chown(tmpbuf,uid,gid);

  va_end(args);
  return(VA_SUCCESS);
}

/************************************************************************/

/* Michael Bowe 21st Aug 2003
 * This function doesnt appear to be used by vpopmail or qmailadmin 
 * Consider it for removal perhaps
 */ 
/* delete a domain/qmail-alias file */
int vdeldotqmail( char *alias, char *domain )
{
 char Dir[MAX_BUFF];
 uid_t uid;
 gid_t gid;
 char tmpbuf[MAX_BUFF];

  if ( vget_assign(domain, Dir, sizeof(Dir), &uid, &gid ) == NULL) {
    return(VA_DOMAIN_DOES_NOT_EXIST);
  }

  snprintf(tmpbuf, sizeof(tmpbuf), "%s/.qmail-%s", Dir, alias);
  if ( unlink(tmpbuf) < 0 ) return(VA_COULD_NOT_OPEN_DOT_QMAIL);
  return(VA_SUCCESS);
}

/************************************************************************/

/*
 * Given the domain name:
 * 
 *   get dir, uid, gid from the users/cdb file (if they are not passed as NULL)
 *
 *   If domain is an alias domain, then domain gets updated to be the real domain
 *   
 * Function will return the domain directory on success
 * or return NULL if the domain does not exist.
 * 
 * This function caches last lookup in memory to increase speed
 */
char *vget_assign(char *domain, char *dir, int dir_len, uid_t *uid, gid_t *gid)
{
 FILE *fs;
 int dlen;
 int i;
 char *ptr;

 static char *in_domain = NULL;
 static int in_domain_size = 0;
 static char *in_dir = NULL;
 static int in_dir_size = 0;

 static uid_t in_uid = -1;
 static gid_t in_gid = -1;

 char cdb_key[MAX_BUFF]; 
 char cdb_file[MAX_BUFF];
 char *cdb_buf;

  /* cant lookup a null domain! */
  if ( domain == NULL || *domain == 0) return(NULL);

  /* if domain matches last lookup, use cached values */
  lowerit(domain);
  if ( in_domain_size != 0 && in_domain != NULL 
    && in_dir != NULL && strcmp( in_domain, domain )==0 ) {

    /* return the vars, if the user has asked for them */
    if ( uid!=NULL ) *uid = in_uid;
    if ( gid!=NULL ) *gid = in_gid;
    if ( dir!=NULL ) snprintf(dir, dir_len, "%s", in_dir);

    /* cached lookup complete, exit out now */
    return(in_dir);
  }

  /* this is a new lookup, free memory from last lookup if necc. */
  if ( in_domain != NULL ) {
    free(in_domain);
    in_domain = NULL;
  }
  if ( in_dir != NULL ) {
    free(in_dir);
    in_dir = NULL;
  }

  /* build up a search string so we can search the cdb file */
  snprintf(cdb_key, sizeof(cdb_key), "!%s-", domain);
  
  /* work out the location of the cdb file */
  snprintf(cdb_file, sizeof(cdb_file), "%s/users/cdb", QMAILDIR);

  /* try to open the cdb file */
  if ( (fs = fopen(cdb_file, "r")) == 0 ) {
    return(NULL);
  }

  /* search the cdb file for our requested domain */
  i = cdb_seek(fileno(fs), cdb_key, strlen(cdb_key), &dlen);
  in_uid = -1;
  in_gid = -1;

  if ( i == 1 ) { 
    /* we found a matching record in the cdb file
     * so next create a storage buffer, and then read it in
     */
    cdb_buf = malloc(dlen);
    i = fread(cdb_buf, sizeof(char), dlen, fs);

    /* format of cdb_buf is :
     * realdomain.com\0uid\0gid\0path\0
     */

    /* get the real domain */
    ptr = cdb_buf;                      /* point to start of cdb_buf (ie realdomain) */
    in_domain_size = strlen(ptr)+1;     /* how long is the domain name? cache the length */
    in_domain = malloc(in_domain_size); /* create storage space for domain cache */
    snprintf(in_domain, in_domain_size, "%s", ptr); /* suck out the domain, store into cache */

    /* get the uid */
    while( *ptr != 0 ) ++ptr;           /* advance pointer past the realdomain */
    ++ptr;                              /* skip over the null */
    in_uid = atoi(ptr);                 /* suck out the uid */
    if ( uid!=NULL) *uid = in_uid;      /* if the user requested the uid, give it to them */

    /* get the gid */
    while( *ptr != 0 ) ++ptr;           /* skip over the uid */
    ++ptr;                              /* skip over the null */
    in_gid = atoi(ptr);                 /* suck out the gid */
    if ( gid!=NULL) *gid = in_gid;      /* if the user requested the gid, give it to them */

    /* get the domain directory */
    while( *ptr != 0 ) ++ptr;           /* skip over the gid */
    ++ptr;                              /* skip over the null */
    if ( dir!=NULL ) strncpy( dir, ptr, dir_len); /* if user requested dir, give it */
    in_dir_size = strlen(ptr)+1;        /* how long is dir? cache the length */
    in_dir = malloc(in_dir_size);       /* create storage space for dir cache */
    snprintf(in_dir, in_dir_size, "%s", ptr); /* suck out the dir, and store it in cache */

    free(cdb_buf);

    /* when vget_assign is called with the domain parameter set as an alias domain,
     * it is meant to replace this alias domain with the real domain
     *
     * in_domain contains the real domain, so do this replacement now.
     *
     * Michael Bowe 21st Aug 2003. Need to watch out for buffer overflows here.
     * We dont know what size domain is, so stick with a conservative limit of MAX_PW_DOMAIN
     * Not sure if this is our best option? the pw entry shouldnt contain any dirs larger
     * than this.
     */
    snprintf(domain, MAX_PW_DOMAIN, "%s", in_domain); 

  } else {
    free(in_domain);
    in_domain = NULL;
    in_domain_size = 0;
  }
  fclose(fs);
  return(in_dir);
}

/************************************************************************/

/* THE USE OF THIS FUNCTION IS DEPRECIATED.
 *
 * None of the vpopmail code uses this function,
 * but it has been left in the source for the time being,
 * to ensure backwards compatibility with some of the popular
 * patches such as Tonix's chkusr
 *
 * This function is scheduled to be removed at a future date 
 *
 * You can obtain same functionality by calling
 *   vget_assign (domain, NULL, 0, NULL, NULL)
 * 
 */

int vget_real_domain (char *domain, int len)
{
  if (domain == NULL) return (0);
  vget_assign (domain, NULL, 0, NULL, NULL);
  return (0);
}

/************************************************************************/

/* This function is typically used to create a user's maildir
 * on-the-fly should it not exist
 * Basically, a dir for the user has been been allocated/stored
 * in the auth backend, but it does not yet exist in the filesystem
 * so we are going to make the dirs now so that mail can be delivered
 *
 * Main use is to call it from vchkpw.c and vdelivermail.c
 * in this format :
 *  vmake_maildir(TheDomain, vpw->pw_dir)
 */

int vmake_maildir(char *domain, char *dir )
{
 char tmpbuf[MAX_BUFF];
 char calling_dir[MAX_BUFF];
 uid_t uid;
 gid_t gid;
 char *tmpstr;
 int i;

  /* record which dir the command was launched from */
  getcwd(calling_dir, sizeof(calling_dir));

  /* set the mask for file creation */
  umask(VPOPMAIL_UMASK);
 
  /* check if domain exists.
   * if domain exists, store the dir into tmpbuf, and store uid and gid
   */
  if ( vget_assign(domain, tmpbuf, sizeof(tmpbuf), &uid, &gid ) == NULL ) {
    return( VA_DOMAIN_DOES_NOT_EXIST );
  }

  /* so, we should have some variables like this now :
   *   dir:    /home/vpopmail/domains/[x]/somedomain.com/[x]/someuser
   *   tmpbuf: /home/vpopmail/domains/[x]/somedomain.com
   */

  /* walk to where the sub directory starts */
  for(i=0,tmpstr=dir;tmpbuf[i]==*tmpstr&&tmpbuf[i]!=0&&*dir!=0;++i,++tmpstr);

  /* walk past trailing slash */
  while ( *tmpstr == '/'  ) ++tmpstr;

  /* tmpstr should now contain : [x]/someuser */

  /* so 1st cd into the domain dir (which should already exist) */
  if ( chdir(tmpbuf) == -1 ) { chdir(calling_dir); return( VA_BAD_DIR); }

  /* Next, create the user's dir
   * ie [x]/someuser
   */
  r_mkdir(tmpstr, uid, gid);

  /* we should now be able to cd into the user's dir */
  if ( chdir(dir) != 0 ) { chdir(calling_dir); return(-1); }

  /* now create the Maildir */
  if (mkdir("Maildir",VPOPMAIL_DIR_MODE) == -1) { chdir(calling_dir); return(-1); }
  if (chdir("Maildir") == -1) { chdir(calling_dir); return(-1); }
  if (mkdir("cur",VPOPMAIL_DIR_MODE) == -1) { chdir(calling_dir); return(-1); }
  if (mkdir("new",VPOPMAIL_DIR_MODE) == -1) { chdir(calling_dir); return(-1); }
  if (mkdir("tmp",VPOPMAIL_DIR_MODE) == -1) { chdir(calling_dir); return(-1); }

  /* set permissions on the user's dir */
  chdir(dir);
  r_chown(dir, uid, gid);

  /* change back to the orignal dir */
  chdir(calling_dir);
  return(0);
}

/************************************************************************/

/* This function allows us to store an crypted password in the user's maildir
 * for use by sqwebmail
 */
int vsqwebmail_pass( char *dir, char *crypted, uid_t uid, gid_t gid )
{
 FILE *fs;
 char tmpbuf1[MAX_BUFF];

  if ( dir == NULL ) return(VA_SUCCESS);
  snprintf(tmpbuf1, sizeof(tmpbuf1), "%s/Maildir/sqwebmail-pass", dir);
  if ( (fs = fopen(tmpbuf1, "w")) == NULL ) {
    return(VA_SQWEBMAIL_PASS_FAIL);
  }
  fprintf(fs, "\t%s\n", crypted);
  fclose(fs);
  chown(tmpbuf1,uid,gid);
  return(0);
}

/************************************************************************/

#ifdef POP_AUTH_OPEN_RELAY 
/* This function is used to grab the user's ip address
 * and add it to the ip's that are allowed to relay mail
 * through this server.
 *
 * For mysql backend, the ip is added to the relay table
 * For cdb backend, the ip is added to the ~vpopmail/etc/open-smtp file
 * 
 * Then the update_rules() function is called which 
 * combines the tcp.smtp rules with the relay-table/open-smtp rules
 * to build a new tcp.smtp.cdb file for tcpserver to use
 *
 * This function is called after a successful pop-auth by vchkpw,
 * (assuming that roaming users are enabled)
 */
int open_smtp_relay()
{
#ifdef USE_SQL
  /* store the user's ip address into the sql relay table */
  if (vopen_smtp_relay()) {
    /* generate a new tcp.smtp.cdb file */
    if (update_rules() != 0) {
      fprintf (stderr, "Error. update_rules failed\n");
      return (-1);
    }
  }
#else
/* if we arent using SQL backend, then we have to maintain the
 * info via the tcp.smtp file
 */
 FILE *fs_cur_file;
 FILE *fs_tmp_file;
#ifdef FILE_LOCKING
 FILE *fs_lok_file;
#endif /* FILE_LOCKING */
 char *ipaddr;
 char *tmpstr;
 time_t mytime;
 int rebuild_cdb = 1;
 char open_smtp_tmp_filename[MAX_BUFF];
 char tmpbuf1[MAX_BUFF];
 char tmpbuf2[MAX_BUFF];

  mytime = time(NULL);

#ifdef FILE_LOCKING
  /* by default the OPEN_SMTP_LOK_FILE is ~vpopmail/etc/open-smtp.lock */
  if ( (fs_lok_file=fopen(OPEN_SMTP_LOK_FILE, "w+")) == NULL) return(-1);
  get_write_lock(fs_lok_file);
#endif /* FILE_LOCKING */

  /* by default the OPEN_SMTP_CUR_FILE is ~vpopmail/etc/open-smtp */
  if ( (fs_cur_file = fopen(OPEN_SMTP_CUR_FILE, "r+")) == NULL ) {
    /* open for read/write failed, so try creating it from scratch */
    if ( (fs_cur_file = fopen(OPEN_SMTP_CUR_FILE, "w+")) == NULL ) {
#ifdef FILE_LOCKING
      unlock_lock(fileno(fs_lok_file), 0, SEEK_SET, 0);
      fclose(fs_lok_file);
#endif /* FILE_LOCKING */
      /* failed trying to access the open-smtp file */
      return(-1);
    }
  }

  /* by default the OPEN_SMTP_TMP_FILE is ~vpopmail/etc/open-smtp.tmp */
  snprintf(open_smtp_tmp_filename, sizeof(open_smtp_tmp_filename),
           "%s.%lu", OPEN_SMTP_TMP_FILE, (long unsigned)getpid());
  /* create the tmp file as open-smtp.tmp.pid */
  fs_tmp_file = fopen(open_smtp_tmp_filename, "w+");

  if ( fs_tmp_file == NULL ) {
#ifdef FILE_LOCKING
    unlock_lock(fileno(fs_lok_file), 0, SEEK_SET, 0);
    fclose(fs_lok_file);
#endif /* FILE_LOCKING */
    /* failed to create the tmp file */
    return(-1);
  }

  ipaddr = get_remote_ip();

  if ( ipaddr == NULL ) {     
#ifdef FILE_LOCKING
    unlock_lock(fileno(fs_lok_file), 0, SEEK_SET, 0);
    fclose(fs_lok_file);
#endif /* FILE_LOCKING */
    /* failed to get user's ip address */
    return(-1);
  }

  /* read in the current open-smtp file */
  while ( fgets(tmpbuf1, sizeof(tmpbuf1), fs_cur_file ) != NULL ) {
    snprintf(tmpbuf2, sizeof(tmpbuf2), "%s", tmpbuf1);
    /* extract the ip address from this line */
    tmpstr = strtok( tmpbuf2, ":");
    /* is this a match for our current ip? */
    if ( strcmp( tmpstr, ipaddr ) != 0 ) {
      /* no match, so copy the line out to our tmp file */
      fputs(tmpbuf1, fs_tmp_file);
    } else {
      /* Found a match. Dont copy this line out to the tmp file.
       * We dont want to echo this same line out, because we are going
       * to write a new version of the line below, with an updated
       * timestamp attached.
       * Also clear the rebuild_cdb flag, because we arent adding
       * any new entries in this case
       */
      rebuild_cdb = 0;
    }
  }
  /* append the current ip address to the tmp file
   * using the format x.x.x.x:ALLOW,RELAYCLIENT="",RBLSMTPD=""<TAB>timestamp
   */
  fprintf( fs_tmp_file, "%s:allow,RELAYCLIENT=\"\",RBLSMTPD=\"\"\t%d\n", 
    ipaddr, (int)mytime);
  fclose(fs_cur_file);
  fclose(fs_tmp_file);

  /* rename the open-smtp.tmp to the be open-smtp */
  rename(open_smtp_tmp_filename, OPEN_SMTP_CUR_FILE);

  /* if we added new entries to the file (or created it for the 1st time)
   * then we need to rebuild our tcp.smtp.cdb based on our newly built
   * open-smtp file.
   */
  if ( rebuild_cdb ) {
    if (update_rules() != 0) {
      fprintf(stderr, "Error. update_rules() failed\n");
      return (-1);
    }
  }

#ifdef FILE_LOCKING
  unlock_lock(fileno(fs_lok_file), 0, SEEK_SET, 0);
  fclose(fs_lok_file);
#endif /* FILE_LOCKING */
#endif /* USE_SQL */
  return(0);
}
#endif /* POP_AUTH_OPEN_RELAY */

/************************************************************************/

#ifdef POP_AUTH_OPEN_RELAY 
/* This function is called by update_rules()
 *
 * It will create a tcprules task sitting and waiting for a new ruleset to be
 * piped into it. It will then compile these rules into a new 
 * tcp.smtp.cdb file
 */
long unsigned tcprules_open()
{
 int pim[2];
 long unsigned pid;
 char bin0[MAX_BUFF];
 char bin1[MAX_BUFF];
 char bin2[MAX_BUFF];
 char *binqqargs[4];

  /* create a filename for use as a tmp file */
  snprintf(relay_tempfile, sizeof(relay_tempfile), "%s.tmp.%ld", TCP_FILE, (long unsigned)getpid());

  /* create a pair of filedescriptors for our pipe */
  if (pipe(pim) == -1)  { return(-1);}

  switch( pid=vfork()){
   case -1:
    /* vfork error. close pipes and exit */
    close(pim[0]); close(pim[1]);
    return(-1);
   case 0:
    close(pim[1]);
    if (vfd_move(0,pim[0]) == -1) _exit(120);

    /* build the command line to update the tcp rules file 
     * It will be of this format :
     * TCPRULES_PROG TCP_FILE.cdb TCP_FILE.cbd.tmp.pid
     * eg /usr/local/bin/tcprules /home/vpopmail/etc/tcp.smtp.cdb  /home/vpopmail/etc/tcp.smtp.tmp.pid
     */ 
    snprintf( bin0, sizeof(bin0), "%s", TCPRULES_PROG);
    snprintf( bin1, sizeof(bin1), "%s.cdb", TCP_FILE);
    snprintf( bin2, sizeof(bin2), "%s", relay_tempfile);

    /* put these strings into an argv style array */
    binqqargs[0] = bin0;
    binqqargs[1] = bin1;
    binqqargs[2] = bin2;
    binqqargs[3] = 0;

    /* run this command now (it will sit waiting for input to be piped in */
    execv(*binqqargs,binqqargs);
  }

  /* tcprules_fdm is a filehandle to this process, which we can pipe rules into */
  tcprules_fdm = pim[1]; close(pim[0]);

  return(pid);
}
#endif /* POP_AUTH_OPEN_RELAY */

/************************************************************************/

int vfd_copy(int to, int from)
{
  if (to == from) return 0;
  if (fcntl(from,F_GETFL,0) == -1) return -1;

  close(to);

  if (fcntl(from,F_DUPFD,to) == -1) return -1;

  return 0;
}

/************************************************************************/

int vfd_move(int to, int from)
{
  if (to == from) return 0;
  if (vfd_copy(to,from) == -1) return -1;
  close(from);
  return 0;
}

/************************************************************************/

#ifdef POP_AUTH_OPEN_RELAY 
/* update_rules() is run whenever 
 * - a new ip added (via open_smtp_relay())
 * or
 * - an old ip removed (via clearopensmtp)
 * from the current list of pop connections
 *
 * It generates a new tcp.smtp.cdb file by doing these steps :
 *   for mysql backend :
 *     copy the tcp.smtp file to a tmp file
 *     append the ip's from the relay table to the tmp file
 *     compile the tmp file into a new tcp.smtp.cdb file 
 *   for cdb backend :
 *     copy the tcp.smtp file to a tmp file
 *     append the ip's from the open-smtp file to the tmp file
 *     compile the tmp file into a new tcp.smtp.cdb file 
 */ 
int update_rules()
{
 FILE *fs;
 long unsigned pid;
 int wstat;
 char tmpbuf1[MAX_BUFF];

#ifndef USE_SQL
 char tmpbuf2[MAX_BUFF];
 char *tmpstr;
#endif

#ifndef REBUILD_TCPSERVER
  return(0);
#endif

  umask(VPOPMAIL_TCPRULES_UMASK);

  /* open up a tcprules task, and leave it sitting waiting for the
   * new set of rules to be piped in (via the filehandle "tcprules_fdm")
   */
  if ((pid = tcprules_open()) < 0) return(-1);

  /* Open the TCP_FILE if it exists.
   * it is typically named /home/vpopmail/etc/tcp.smtp
   */
  fs = fopen(TCP_FILE, "r");
  if ( fs != NULL ) {
    /* copy the contents of the current tcp.smtp file into the tcprules pipe */
    while ( fgets(tmpbuf1, sizeof(tmpbuf1), fs ) != NULL ) {
      write(tcprules_fdm,tmpbuf1, strlen(tmpbuf1));
    }
    fclose(fs);
  }

#ifdef USE_SQL
  /* suck out a list of ips stored in the 'relay' table
   * and write these into 'tcp.smtp' format for the tcprules pipe
   */
  vupdate_rules(tcprules_fdm);

#else

  /* open up the file that contains the list of recent open connections
   * (by default this is ~vpopmail/etc/open-smtp)
   * This file is generated by the open_smtp() function
   * the file has the following format :
   * x.x.x.x:ALLOW,RELAYCLIENT="",RBLSMTPD=""<TAB>timestamp
   */
  fs = fopen(OPEN_SMTP_CUR_FILE, "r");
  if ( fs != NULL ) {
    /* read each of the recently open connections. */
    while ( fgets(tmpbuf1, sizeof(tmpbuf1), fs ) != NULL ) {
      snprintf(tmpbuf2, sizeof(tmpbuf2), "%s", tmpbuf1);
      /* dump the TAB and everything after it */
      tmpstr = strtok( tmpbuf2, "\t");
      strncat(tmpstr, "\n", sizeof(tmpstr)-strlen(tmpstr)-1);
      /* write the line out to the tcprules pipe */
      write(tcprules_fdm,tmpstr, strlen(tmpstr));
    }
    fclose(fs);
  }
#endif

  /* close the pipe to the tcprules process. This will cause
   * tcprules to generate a new tcp.smtp.cdb file 
   */
  close(tcprules_fdm);  

  /* wait untill tcprules finishes so we don't have zombies */
  while(wait(&wstat)!= pid);

  /* if tcprules encounters an error, then the tempfile will be
   * left behind on the disk. We dont want this because we could
   * possibly end up with a large number of these files cluttering
   * the directory. Therefore we will use unlink now to make
   * sure to zap the temp file if it still exists
   */
  if ( unlink(relay_tempfile) == 0 ) {
    fprintf(stderr, "Warning: update_rules() - tcprules failed\n");
  }

  /* correctly set the ownership of the tcp.smtp.cdb file */
  snprintf(tmpbuf1, sizeof(tmpbuf1), "%s.cdb", TCP_FILE);
  chown(tmpbuf1,VPOPMAILUID,VPOPMAILGID);

  return(0);
}
#endif

/************************************************************************/

int vexit(int err)
{
  vclose();
  exit(err);
}

/************************************************************************/

/* zap the maildirsize file from a users dir */
void remove_maildirsize(char *dir) {
 char maildirsize[MAX_BUFF];
 FILE *fs;

  snprintf(maildirsize, sizeof(maildirsize), "%s/Maildir/maildirsize", dir);
  if ( (fs = fopen(maildirsize, "r+"))!=NULL) {
    fclose(fs);
    unlink(maildirsize);
  }
}

/************************************************************************/

/* run some tests on the contents of a vpqw struct */
int vcheck_vqpw(struct vqpasswd *inpw, char *domain)
{

  if ( inpw == NULL )   return(VA_NULL_POINTER );
  if ( domain == NULL ) return(VA_NULL_POINTER);

  if ( inpw->pw_name == NULL )         return(VA_NULL_POINTER);
  if ( inpw->pw_passwd == NULL )       return(VA_NULL_POINTER);
  if ( inpw->pw_gecos == NULL )        return(VA_NULL_POINTER);
  if ( inpw->pw_dir == NULL )          return(VA_NULL_POINTER);
  if ( inpw->pw_shell == NULL )        return(VA_NULL_POINTER);
#ifdef CLEAR_PASS
  if ( inpw->pw_clear_passwd == NULL ) return(VA_NULL_POINTER);
#endif

  /* when checking for excess size using strlen, the check needs use >= because you
   * have to allow 1 char for null termination
   */ 
  if ( strlen(inpw->pw_name) >= MAX_PW_NAME )   return(VA_USER_NAME_TOO_LONG);
  if ( strlen(inpw->pw_name) == 1 )             return(VA_ILLEGAL_USERNAME);
  if ( strlen(domain) >= MAX_PW_DOMAIN )        return(VA_DOMAIN_NAME_TOO_LONG);
  if ( strlen(inpw->pw_passwd) >= MAX_PW_PASS ) return(VA_PASSWD_TOO_LONG);
  if ( strlen(inpw->pw_gecos) >= MAX_PW_GECOS ) return(VA_GECOS_TOO_LONG);
  if ( strlen(inpw->pw_dir) >= MAX_PW_DIR )     return(VA_DIR_TOO_LONG);
  if ( strlen(inpw->pw_shell) >= MAX_PW_QUOTA ) return(VA_QUOTA_TOO_LONG);
#ifdef CLEAR_PASS
  if ( strlen(inpw->pw_clear_passwd) >= MAX_PW_CLEAR_PASSWD )
                                                return(VA_CLEAR_PASSWD_TOO_LONG);
#endif
  return(VA_SUCCESS);

}

/************************************************************************/

char *vrandom_pass(char *buffer, int len)
/* write a random password of 'len' characters to buffer and return it */
{
  int gen_char_len; 
  int i, k; 
  static int seeded = 0;

  if (buffer == NULL) return buffer;

  gen_char_len = strlen(gen_chars);

  if (!seeded) {
    seeded = 1;
    srand(time(NULL)^(getpid()<<15));
  }

  for (i = 0; i < len; i++) {
    k = rand()%gen_char_len;
    buffer[i] = gen_chars[k];
  }
  buffer[len] = '\0';  /* NULL terminator */

  return buffer;
}

char *vgen_pass(int len)
/* old function to generate a random password (replaced by vrandom_pass) */
{
  char *p;

  p = malloc(len + 1);
  if (p == NULL) return NULL;
  return (vrandom_pass (p, len));
}


/************************************************************************/

/* if inchar is valid, return 1
 * if inchar is invalid, return 0
 *
 * Michael Bowe 15th August 2003
 * This  function isnt used by vpopmail, cantidate for removal?
 */
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

/************************************************************************/

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

/************************************************************************/

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

/************************************************************************/

/* add an alias domain to the system  */
int vaddaliasdomain( char *alias_domain, char *real_domain)
{
 int err;
 uid_t uid;
 gid_t gid;
 char Dir[MAX_BUFF];
 
  lowerit(alias_domain);
  lowerit(real_domain);

  if ( (err=is_domain_valid(real_domain)) != VA_SUCCESS ) return(err);
  if ( (err=is_domain_valid(alias_domain)) != VA_SUCCESS ) return(err);

  /* make sure the alias domain does not exceed the max storable size */
  if (strlen(alias_domain) >= MAX_PW_DOMAIN) {
    return(VA_DOMAIN_NAME_TOO_LONG);
  }

  /* Make sure that the alias_domain doesnt already exist */
  /* Michael Bowe 21st Aug 2003 
   * Will the alias_domain get overwritten with the real_domain
   * by the call below?
   * Could this mess things up for the calling function?
   */
  if (( vget_assign(alias_domain, NULL, 0, NULL, NULL)) != NULL) {
    return(VA_DOMAIN_ALREADY_EXISTS);
  }

  /* Make sure the real domain exists */
  if (( vget_assign(real_domain, Dir, sizeof(Dir), &uid, &gid)) == NULL) {
    return(VA_DOMAIN_DOES_NOT_EXIST);
  }

  if (strcmp(alias_domain, real_domain)==0) {
    fprintf(stderr, "Error. alias and real domain are the same\n");
    return(VA_DOMAIN_ALREADY_EXISTS);
  }

  /* Add the domain to the assign file */
  add_domain_assign( alias_domain, real_domain, Dir, uid, gid );

  /* signal qmail-send, so it can see the changes */
  signal_process("qmail-send", SIGHUP);

  return(VA_SUCCESS);
}

/************************************************************************/

                /* properly handle the following formats:
                 * "1M", "1024K", "1048576" (set 1 MB quota)
                 * "1MB", "1024KB" (set 1 MB quota)
                 * "NOQUOTA" (no quota)
                 * "1mbs,1000C" (1 MB size, 1000 message limit)
                 * "1048576S,1000C" (1 MB size, 1000 message limit)
                 * "1000C,10MBS" (10 MB size, 1000 message limit)
                 */

char *format_maildirquota(const char *q) {
int     i;
double	quota_size;
long	quota_count;
char	*p;
static char    tempquota[128];

    if (strcmp (q, "NOQUOTA") == 0) {
      strcpy (tempquota, "NOQUOTA");
      return tempquota;
    }

    /* translate the quota to a number, or leave it */
    quota_size = -1.0;
    quota_count = -1;
    snprintf (tempquota, sizeof(tempquota), "%s", q);
    p = strtok (tempquota, ",");
    while (p != NULL) {
      i = strlen(p) - 1;
      if (p[i] == 'C') { /* specify a limit on the number of messages (COUNT) */
        quota_count = atol(p);
      } else { /* specify a limit on the size */
        /* strip optional trailing S */
        if ((p[i] == 'S') || (p[i] == 's')) p[i--] = '\0';
        /* strip optional trailing B (for KB, MB) */
        if ((p[i] == 'B') || (p[i] == 'b')) p[i--] = '\0';

        quota_size = atof(p);
        if ((p[i] == 'M') || (p[i] == 'm')) quota_size *= 1024 * 1024;
        if ((p[i] == 'K') || (p[i] == 'k')) quota_size *= 1024;
      }
      p = strtok (NULL, ",");
    }

    if (quota_count == -1)
      if (quota_size == -1.0) strcpy (tempquota, ""); /* invalid quota */
      else sprintf (tempquota, "%.0fS", quota_size);
    else if (quota_size == -1.0)
      sprintf (tempquota, "%luC", quota_count);
    else
      sprintf (tempquota, "%.0fS,%luC", quota_size, quota_count);

    return tempquota;
}

/************************************************************************/

/* returns a 39 character Date: header with trailing newline and NULL */
char *date_header()
{
  static char dh[39];
  time_t now;
  struct tm *tm;

  static char *montab[12] = {
  "Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"
  };
  static char *wday[7] = {
  "Sun","Mon","Tue","Wed","Thu","Fri","Sat"
  };

  /* look up current time and fill tm structure */
  time(&now);
  tm = gmtime(&now);

  snprintf (dh, sizeof(dh),
    "Date: %s, %02u %s %u %02u:%02u:%02u +0000\n",
    wday[tm->tm_wday], tm->tm_mday, montab[tm->tm_mon], tm->tm_year + 1900,
    tm->tm_hour, tm->tm_min, tm->tm_sec);

  return dh;
}

char *get_remote_ip()
{
  char *ipenv;
  static char ipbuf[30];
  char *ipaddr;
  char *p;

  ipenv = getenv("TCPREMOTEIP");
  if ((ipenv == NULL) || (strlen(ipenv) > sizeof(ipbuf))) return ipenv;

  strcpy (ipbuf, ipenv);
  ipaddr = ipbuf;

  /* Convert ::ffff:127.0.0.1 format to 127.0.0.1
   * While avoiding buffer overflow.
   */
  if (*ipaddr == ':') {
    ipaddr++;
    if (*ipaddr != '\0') ipaddr++;
    while((*ipaddr != ':') && (*ipaddr != '\0')) ipaddr++;
    if (*ipaddr != '\0') ipaddr++;
  }

  /* remove invalid characters */
  for (p = ipaddr; *(p += strspn(p, ok_env_chars)); ) {*p='_';}

  return ipaddr;  
}


char *maildir_to_email(const char *maildir)
{
 static char email[256];
 int i, j=0;
 char *pnt, *last;

    memset(email, 0, sizeof(email));
    for(last=NULL, pnt=(char *)maildir; (pnt=strstr(pnt,"/Maildir/"))!=NULL; pnt+=9 ){
        last = pnt;
    }
    if(!last) return "";

    /* so now pnt at begin of last Maildir occurence
     * going toward start of maildir we can get username
     */
    pnt = last;

    for( i=(pnt-maildir); (i > 1 && *(pnt-1) != '/'); --pnt, --i);

    for( ; (*pnt && *pnt != '/' && j < 255); ++pnt) {
        email[j++] = *pnt;
    }

    email[j++] = '@';

    for (last=NULL, pnt=(char *)maildir; (pnt=strstr(pnt, "/" DOMAINS_DIR "/")); pnt+=strlen("/" DOMAINS_DIR "/")) {
        last = pnt;
    }

    if(!last) return "";

    pnt = last + strlen(DOMAINS_DIR) + 2;
    while ( *(pnt+1) == '/' ) pnt+=2;  /* skip over hash directory names */
    for( ; (*pnt && *pnt != '/' && j < 255); ++pnt, ++j ) {
      email[j] = *pnt;
    }

    email[j] = 0;

    return( email );
}

/* escape these characters out of strings: ', \, " */
#define ESCAPE_CHARS "'\"\\"

/* qnprintf - Custom version of snprintf for creating SQL queries with escaped
 *            strings.
 *
 * int qnprintf (char *buffer, size_t size, const char *format, ...)
 *
 *   buffer - buffer to print string to
 *   size   - size of buffer
 *   format - a printf-style format string*
 *   ...    - variable arguments for the format string
 *
 *  NOTE: Currently supported formats: %%, %s, %d/%i, %u, %ld/%li, %lu
 *  Since this function was designed to build SQL queries with escaped data,
 *  the formats don't support any extended options.
 *
 * Returns the number of characters that would have been printed to buffer
 * if it was big enough.  (i.e., if return value is larger than (size-1),
 * buffer received an incomplete copy of the formatted string).
 *
 * It is possible to call qnprintf with a NULL buffer of 0 bytes to determine
 * how large the buffer needs to be.  This is inefficient, as qnprintf has
 * to run twice.
 *
 * qnprintf written February 2004 by Tom Collins <tom@tomlogic.com>
 */
int qnprintf (char *buffer, size_t size, const char *format, ...)
{
	va_list ap;
	int printed;   /* number of characters printed */
	const char *f; /* current position in format string */
	char *b;       /* current position in output buffer */
	char n[20];    /* buffer to hold string representation of number */
	
	char *s;       /* pointer to string to insert */

	if (buffer == NULL && size > 0) return -1;

	va_start (ap, format);

	printed = 0;
	b = buffer;
	for (f = format; *f != '\0'; f++) {
		if (*f != '%') {
			if (++printed < size) *b++ = *f;
		} else {
			f++;
			s = n;
			switch (*f) {
				case '%':
					strcpy (n, "%");
					break;
					
				case 'd':
				case 'i':
					snprintf (n, sizeof(n), "%d", va_arg (ap, int));
					break;
					
				case 'u':
					snprintf (n, sizeof(n), "%u", va_arg (ap, unsigned int));
					break;
					
				case 'l':
					f++;
					switch (*f) {
						case 'd':
						case 'i':
							snprintf (n, sizeof(n), "%ld", va_arg (ap, long));
							break;
					
						case 'u':
							snprintf (n, sizeof(n), "%lu", va_arg (ap, unsigned long));
							break;

						default:
							strcpy (n, "*");
					}
					break;
										
				case 's':
					s = va_arg (ap, char *);
					break;
					
				default:
					strcpy (n, "*");
			}
			while (*s != '\0') {
				if (strchr (ESCAPE_CHARS, *s) != NULL) {
					if (++printed < size) *b++ = '\\';
				}
				if (++printed < size) *b++ = *s;
				s++;
			}
		}
	}

	va_end (ap);

	*b = '\0';

	/* If the query doesn't fit in the buffer, zero out the buffer.  An
	 * incomplete query could be very dangerous (say if a WHERE clause
	 * got dropped from a DELETE).
	 */
	if (printed >= size) {
		memset (buffer, '\0', size);
	}
	
	return printed;
}

