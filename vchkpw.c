/*
 * vchkpw
 * This is a complete re-write of the 4.9 and below vchkpw versions
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
 * 
 * Purpose: vchkpw a pop authentication module for qmail-pop3d server
 * 
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <sys/wait.h>
#include <pwd.h>
#include <sys/types.h>
#include "config.h"
#include "vpopmail.h"
#include "vlog.h"
#include "vauth.h"

#ifdef HAS_SHADOW
#include <shadow.h>
#endif

/* Definitions */
#define VCHKPW_USER     "USER="
#define VCHKPW_HOME     "HOME="
#define VCHKPW_SHELL    "SHELL=NOLOGIN"
#define VCHKPW_VPOPUSER "VPOPUSER="

/* For tracking ip of client asking for pop service */
char *IpAddr;

/* storage of authentication information */
#define AUTH_SIZE 156
#define AUTH_INC_SIZE 155
char TheName[AUTH_SIZE];
char TheUser[AUTH_SIZE];
char ThePass[AUTH_SIZE];
char TheCrypted[AUTH_SIZE];
char TheDomain[AUTH_SIZE];

/* log line buffer */
#define LOG_LINE_SIZE 500
char LogLine[LOG_LINE_SIZE];

/* environment variable buffers */
#define MAX_ENV_BUF 100
static char envbuf1[MAX_ENV_BUF];
static char envbuf2[MAX_ENV_BUF];
static char envbuf3[MAX_ENV_BUF];
static char envbuf4[MAX_ENV_BUF];

/* shared data */
uid_t pw_uid;
gid_t pw_gid;
char *pw_dir=NULL;
struct vqpasswd *vpw = NULL;

/* Forward declaration */
char *sysc(char *mess);
void login_virtual_user();
void login_system_user();
void read_user_pass();
void vlog(int verror, char *TheUser, char *TheDomain, char *ThePass, char *TheName, char *IpAddr, char *LogLine);
void vchkpw_exit(int err);
void run_command(char *prog);

int main( int argc, char **argv)
{

    if ( (IpAddr = getenv("TCPREMOTEIP")) == NULL) IpAddr="";

    /* read in the user name and password from file descriptor 3 */
    read_user_pass();

    if ( parse_email( TheName, TheUser, TheDomain, AUTH_SIZE) != 0 ) {
        snprintf(LogLine, LOG_LINE_SIZE, 
            "vchkpw: invalid user/domain characters %s:%s", TheName, IpAddr);
	vlog(VLOG_ERROR_PASSWD, TheUser, TheDomain, ThePass, TheName, 
          IpAddr, LogLine);
        vchkpw_exit(20);
    }

    /* check if this virtual domain is in the system 
     * we look in /var/qmail/users/cdb file
     * and while we are at it, let's get the domains
     * user id and group id.
     */
    if ( (vpw = vauth_getpw(TheUser, TheDomain)) != NULL ) {

	vget_assign(TheDomain,NULL,0,&pw_uid,&pw_gid);
        login_virtual_user();

    /* if it is not in the virtual domains 
     * then check the user in /etc/passwd
     */
#ifdef ENABLE_PASSWD
    } else if ( ENABLE_PASSWD == 1 ) {
	login_system_user();
#endif

    } else {
        snprintf(LogLine, LOG_LINE_SIZE, 
            "vchkpw: vpopmail user not found %s@%s:%s", 
            TheUser, TheDomain, IpAddr);
	vlog(VLOG_ERROR_LOGON, TheUser, TheDomain, ThePass, TheName, IpAddr, LogLine);
        vchkpw_exit(3);
    }
    vclose();

    /* The user is authenticated, now setup the environment
     * for qmail-pop3d
     */

    /* Set the programs effective group id */ 
    if ( setgid(pw_gid) == -1 ) {
        snprintf(LogLine, LOG_LINE_SIZE, 
            "vchkpw: setgid %lu failed errno %d %s@%s:%s", 
          (long unsigned)pw_gid, errno, TheUser, TheDomain, IpAddr);
	vlog(VLOG_ERROR_INTERNAL, TheUser, TheDomain, ThePass, TheName, IpAddr, LogLine);
        vchkpw_exit(4);
    }

    /* Set the programs effective user id */ 
    if ( setuid(pw_uid) == -1 ) {
        snprintf(LogLine, LOG_LINE_SIZE, 
            "vchkpw: setuid %lu failed errno %d %s@%s:%s", 
          (long unsigned)pw_uid, errno, TheUser, TheDomain, IpAddr);
	vlog(VLOG_ERROR_INTERNAL, TheUser, TheDomain, ThePass, TheName, IpAddr, LogLine);
        vchkpw_exit(5);
    }

    /* Change to the users Maildir directory */
    if (chdir(pw_dir) == -1) {
      if ( vpw!=NULL) { 
        if ( vmake_maildir(TheDomain, vpw->pw_dir )!= VA_SUCCESS ) {
          snprintf(LogLine, LOG_LINE_SIZE, 
            "vchkpw: autocreate dir errno %d %s %s@%s:%s", 
            errno, pw_dir, TheUser, TheDomain, IpAddr);
	  vlog(VLOG_ERROR_INTERNAL, TheUser, TheDomain, ThePass, 
            TheName, IpAddr, LogLine);
          vchkpw_exit(6);
        }
        chdir(pw_dir);
      } else {
        snprintf(LogLine, LOG_LINE_SIZE, 
          "vchkpw: chdir failed errno %d %s %s@%s:%s", 
          errno, pw_dir, TheUser, TheDomain, IpAddr);
	vlog(VLOG_ERROR_INTERNAL, TheUser, TheDomain, ThePass, 
          TheName, IpAddr, LogLine);
        vchkpw_exit(6);
     }
    }

    /* The the VCHKPW_USER variable */
    strncpy(envbuf1,VCHKPW_USER,MAX_ENV_BUF);
    strncat(envbuf1,TheUser,MAX_ENV_BUF);
    if ( putenv(envbuf1) == -1 ) {
        snprintf(LogLine, LOG_LINE_SIZE, 
            "vchkpw: putenv(USER) failed errno %d %s@%s:%s", 
          errno, TheUser, TheDomain, IpAddr);
	vlog(VLOG_ERROR_INTERNAL, TheUser, TheDomain, ThePass, TheName, IpAddr, LogLine);
        vchkpw_exit(7);
    }

    /* Now HOME */
    strncpy(envbuf2,VCHKPW_HOME,MAX_ENV_BUF);
    strncat(envbuf2,pw_dir,MAX_ENV_BUF);
    if ( putenv(envbuf2) == -1 ) {
        snprintf(LogLine, LOG_LINE_SIZE, 
            "vchkpw: putenv(HOME) failed errno %d %s@%s:%s", 
          errno, TheUser, TheDomain, IpAddr);
	vlog(VLOG_ERROR_INTERNAL, TheUser, TheDomain, ThePass, TheName, IpAddr, LogLine);
        vchkpw_exit(8);
    }

    /* Now SHELL */
    strncpy(envbuf3,VCHKPW_SHELL,MAX_ENV_BUF);
    if ( putenv(envbuf3) == -1 ) {
        snprintf(LogLine, LOG_LINE_SIZE, 
            "vchkpw: putenv(SHELL) failed errno %d %s@%s:%s", 
          errno, TheUser, TheDomain, IpAddr);
	vlog(VLOG_ERROR_INTERNAL, TheUser, TheDomain, ThePass, TheName, IpAddr, LogLine);
        vchkpw_exit(9);
    }

    /* Now VPOPUSER */
    strncpy(envbuf4,VCHKPW_VPOPUSER,MAX_ENV_BUF);
    strncat(envbuf4,TheName,MAX_ENV_BUF);
    if ( putenv(envbuf4) == -1 ) {
        snprintf(LogLine, LOG_LINE_SIZE,
            "vchkpw: putenv(VPOPUSER) failed errno %d %s@%s:%s", 
            errno, TheUser, TheDomain, IpAddr);
	vlog(VLOG_ERROR_INTERNAL, TheUser, TheDomain, ThePass, TheName, IpAddr, LogLine);
        vchkpw_exit(10);
    }


    /* close the log connection */
    if ( ENABLE_LOGGING > 0 ) {
        closelog();
    }

    /* And now a simple way to kick off the next program */
    execvp(argv[1],argv+1);

    /* all done, time to release resources and go away */ 
    exit(0);

}

/* clean a buffer for syslog */
char *sysc(char *mess)
{
 char *ripper;

	for(ripper=mess;*ripper!=0;++ripper) {
		if ( *ripper=='%' ) {
                    *ripper = '#';
                }
        }
	return(mess);
}

void read_user_pass()
{
 int i,j,l;

    /* Read the user and password from file descriptor 3
     * use TheDomain variable as temporary storage of the 
     * full incoming line 
     */ 
    memset(TheDomain,0,AUTH_SIZE);
    for(i=0;i<AUTH_SIZE;i+=j){
        
        /* read a chunk */
        j = read(3,&TheDomain[i],AUTH_SIZE-i-1);

        /* on error exit out */
        if ( j == -1 ) {     
            printf("vchkpw: what the hell are you doing running vchkpw on the command line!! It's only for talking with qmail-popup and qmail-pop3d.\n");
            vchkpw_exit(11);
        } else if ( j == 0 ) {
            break;
        }
    }

    /* close the user/pass file descriptor */
    close(3);

    /* parse out the name */
    memset(TheName,0,AUTH_SIZE);
    for(l=0;l<AUTH_INC_SIZE;++l){
        TheName[l] = TheDomain[l];
        if ( TheName[l] == 0 ) break;
        if (l==i)break;
    }

    /* parse out the password */
    memset(ThePass,0,AUTH_SIZE);
    for(j=0,++l;l<AUTH_INC_SIZE;++j,++l){
        ThePass[j] = TheDomain[l];
        if ( ThePass[j] == 0 ) break;
        if (l==i)break;
    }

    /* open the log if configured */
    if ( ENABLE_LOGGING > 0 ) {
        openlog(LOG_NAME,LOG_PID,LOG_MAIL);
    }

    if ( TheName[0] == 0 ) {
        snprintf(LogLine, LOG_LINE_SIZE, 
            "vchkpw: null user name given %s:%s", TheName, IpAddr);
	vlog(VLOG_ERROR_LOGON, TheUser, TheDomain, ThePass, TheName, IpAddr, LogLine);
        vchkpw_exit(12);
    }

    if ( ThePass[0] == 0 ) {
        snprintf(LogLine, LOG_LINE_SIZE, 
            "vchkpw: null password given %s:%s", TheName, IpAddr);
	vlog(VLOG_ERROR_PASSWD, TheUser, TheDomain, ThePass, TheName, IpAddr, LogLine);
        vchkpw_exit(13);
    }
}

void login_virtual_user()
{
    /* If thier directory path is empty make them a new one */
    if ( vpw->pw_dir == NULL || vpw->pw_dir[0]==0 ) {
        if ( make_user_dir(vpw->pw_name, TheDomain, pw_uid, pw_gid)==NULL){
       	    snprintf(LogLine, LOG_LINE_SIZE, 
                    "vchkpw: dir auto create failed %s@%s:%s", 
        	    TheUser, TheDomain, IpAddr);
	    vlog(VLOG_ERROR_INTERNAL, TheUser, TheDomain, ThePass, TheName, IpAddr, LogLine);
            vchkpw_exit(14);
        }
    }

#ifdef ENABLE_LEARN_PASSWORDS
    /* check for a valid vpopmail passwd field */
    if ( vpw->pw_passwd==NULL||vpw->pw_passwd[0]==0) {
        mkpasswd3(ThePass,TheCrypted, AUTH_SIZE);
        vpw->pw_passwd = TheCrypted;
        vpw->pw_clear_passwd = ThePass;
        vauth_setpw(vpw, TheDomain);
#ifdef POP_FETCH
        if ( pop_init(vpw, "") {
          while (pop_loop) == 1 );
        }
#endif
    }
#else
    if ( vpw->pw_passwd==NULL||vpw->pw_passwd[0]==0) {
       	snprintf(LogLine, LOG_LINE_SIZE, 
          "vchkpw: user has no password %s@%s:%s", 
          TheUser, TheDomain, IpAddr);
	vlog(VLOG_ERROR_INTERNAL, TheUser, TheDomain, ThePass, TheName, 
          IpAddr, LogLine);
        vchkpw_exit(15);
    }
#endif

    /* Encrypt the clear text password using the crypted 
     * password as the salt then
     * check if it matches the encrypted password 
     * If it does not match, log errors if requested
     * and exit 
     */
    if ( strcmp(crypt(ThePass,vpw->pw_passwd),vpw->pw_passwd) != 0 ) {
        if ( ENABLE_LOGGING==1||ENABLE_LOGGING==2){
            snprintf(LogLine, LOG_LINE_SIZE, "vchkpw: password fail %s@%s:%s",
                TheUser, TheDomain, IpAddr);
        } else if ( ENABLE_LOGGING==3||ENABLE_LOGGING==4){
            snprintf(LogLine, LOG_LINE_SIZE,
                "vchkpw: password fail %s %s@%s:%s",
                ThePass, TheUser, TheDomain, IpAddr);
        } else { 
            LogLine[0] = 0;
        }
        vlog( VLOG_ERROR_PASSWD, TheUser, TheDomain, ThePass, TheName, 
            IpAddr, LogLine);
        vchkpw_exit(3);
    }

#ifdef ENABLE_LEARN_PASSWORDS
#ifdef CLEAR_PASS 
    /* User with pw_clear_passwd unset but pw_passwd set
     * should have the pw_clear_passwd field filled in
     */
    if ( vpw->pw_clear_passwd==NULL||vpw->pw_clear_passwd[0]==0) {
       vpw->pw_clear_passwd = ThePass;
       vauth_setpw(vpw, TheDomain);
    }
#endif
#endif


    /* They are authenticated now, check for restrictions
     * Check if they are allowed pop access 
     */
    if ( vpw->pw_gid & NO_POP ) {
        snprintf(LogLine, LOG_LINE_SIZE, 
            "vchkpw: pop access denied %s@%s:%s", 
            TheUser, TheDomain, IpAddr);
	vlog(VLOG_ERROR_ACCESS, TheUser, TheDomain, ThePass, TheName, IpAddr, LogLine);
        vchkpw_exit(0);
    }

    /* They are authenticated, log the success if configured */
    snprintf(LogLine, LOG_LINE_SIZE, "vchkpw: login success %s@%s:%s",
      TheUser, TheDomain, IpAddr);
    vlog(VLOG_AUTH, TheUser, TheDomain, ThePass, TheName, IpAddr, LogLine);


    /* If authentication logging is enabled
     * update the authentication time on the account
     */
#ifdef ENABLE_AUTH_LOGGING
    vset_lastauth(TheUser,TheDomain,IpAddr);
#endif

#ifdef POP_AUTH_OPEN_RELAY
    /* Check if we should open up relay for this account */
    if ( (vpw->pw_gid & NO_RELAY) == 0 ) {
        open_smtp_relay();        
    }
#endif

    /* Save the directory pointer */
    pw_dir = vpw->pw_dir;

}

#ifdef ENABLE_PASSWD
void login_system_user()
{
  struct passwd *pw;
#ifdef HAS_SHADOW
  struct spwd *spw;
#endif
    if ((pw=getpwnam(TheUser)) == NULL ) {
        snprintf(LogLine, LOG_LINE_SIZE, "vchkpw: system user not found %s:%s", 
          TheUser, IpAddr);
        vlog(VLOG_ERROR_LOGON, TheUser, TheDomain, ThePass, TheName, IpAddr, LogLine);
        vchkpw_exit(21);
    }
#ifdef HAS_SHADOW
    if ((spw = getspnam(TheUser)) == NULL) {
        snprintf(LogLine, LOG_LINE_SIZE, 
            "vchkpw: system user shadow entry not found %s:%s", 
            TheName, IpAddr);
	vlog(VLOG_ERROR_LOGON, TheUser, TheDomain, ThePass, TheName, IpAddr, LogLine);
        vchkpw_exit(22);
    }

    if ( strcmp(crypt(ThePass,spw->sp_pwdp),spw->sp_pwdp) != 0 ) {
#else
    if ( strcmp(crypt(ThePass,pw->pw_passwd),pw->pw_passwd) != 0 ) {
#endif
        if (ENABLE_LOGGING==1||ENABLE_LOGGING==2) {
            snprintf(LogLine, LOG_LINE_SIZE,
                "vchkpw: system password fail %s:%s", TheName, IpAddr);
        } else if (ENABLE_LOGGING==3||ENABLE_LOGGING==4) {
            snprintf(LogLine, LOG_LINE_SIZE,
                "vchkpw: system password fail %s %s:%s",
                ThePass, TheName, IpAddr);
        } else { 
            LogLine[0] = 0;
        }
        vlog(VLOG_ERROR_PASSWD, TheUser, TheDomain, ThePass, TheName, IpAddr, LogLine);
        vchkpw_exit(23);
    }
    pw_uid = pw->pw_uid;
    pw_gid = pw->pw_gid;
    pw_dir = pw->pw_dir;
#ifdef POP_AUTH_OPEN_RELAY
    open_smtp_relay();    
#endif

}
#endif

void vchkpw_exit(int err)
{
    if ( ENABLE_LOGGING > 0 ) {
        closelog();
    }
    vclose();
    exit(err);
}

/* log messages and figure out what type they are and where they should go depending on configure options */
/* any one of the pointers can be null, i.e. the information is not available */
/* messages are autmatically cleaned for syslog if it is necessary */
void vlog(int verror, char *TheUser, char *TheDomain, char *ThePass, char *TheName, char *IpAddr, char *LogLine) {
    /* always log to syslog if enabled */
    if ( (verror == VLOG_ERROR_PASSWD) && ( ENABLE_LOGGING==1 || ENABLE_LOGGING==2 || ENABLE_LOGGING==3 || ENABLE_LOGGING==4 ) ) {
        syslog(LOG_NOTICE,sysc(LogLine));
    } else if ( verror == VLOG_ERROR_INTERNAL ) {
        syslog(LOG_NOTICE,sysc(LogLine));
    } else if ( verror == VLOG_ERROR_LOGON ) {
        syslog(LOG_NOTICE,sysc(LogLine));
    } else if ( verror == VLOG_ERROR_ACCESS ) {
        syslog(LOG_NOTICE,sysc(LogLine));
    } else if ( verror == VLOG_AUTH && ( ENABLE_LOGGING == 1 || ENABLE_LOGGING == 4 ) ) {
        syslog(LOG_NOTICE,sysc(LogLine));
    }
#ifdef ENABLE_MYSQL_LOGGING
    /* always log to mysql if mysql logging is enabled and it is not internal error */
    if ( (ENABLE_MYSQL_LOGGING > 0) && (verror != VLOG_ERROR_INTERNAL) ) {
        if ( (logmysql(verror, TheUser, TheDomain, ThePass, TheName, IpAddr, LogLine) ) != 0 ) {
            syslog(LOG_NOTICE,"vchkpw: can't write MySQL logs");
        }
    }
#endif
}
