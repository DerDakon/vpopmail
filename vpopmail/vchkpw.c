/*
 * $Id: vchkpw.c,v 1.3 2003-10-07 00:56:53 tomcollins Exp $
 * Copyright (C) 1999-2003 Inter7 Internet Technologies, Inc.
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
#include "vlimits.h"

/* for cram-md5 */
#include "global.h"
#include "md5.h"
#include "hmac_md5.h"
static char hextab[]="0123456789abcdef";

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

/* Embed the port in the log when smtp-auth is used */
char VchkpwLogName[12];

/* For logging, relay info */
int LocalPort;

/* storage of authentication information */
#define AUTH_SIZE 156
#define AUTH_INC_SIZE 155
char TheName[AUTH_SIZE];
char TheUser[AUTH_SIZE];
char ThePass[AUTH_SIZE];
char TheResponse[AUTH_SIZE];
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
int authcram(unsigned char *challenge, unsigned char *response, unsigned char *password);
int authapop(unsigned char *password, unsigned char *timestamp, unsigned char *clearpass);

#define POP_CONN  0
#define SMTP_CONN 1
#define IMAP_CONN 2

int ConnType = 0;

int main( int argc, char **argv)
{
 char *tmpstr;

  if ( (IpAddr = getenv("TCPREMOTEIP"))  == NULL) IpAddr="";
  if ( (tmpstr = getenv("TCPLOCALPORT")) == NULL) LocalPort = 110;
  else LocalPort = atoi(tmpstr);

  /* Check which port they are coming in on and 
   * setup the log name and connection type
   */
  switch(LocalPort) {
    case 25:
      strcpy(VchkpwLogName, "vchkpw-smtp");
      ConnType = SMTP_CONN;
      break;
    case 110:
      strcpy(VchkpwLogName, "vchkpw-pop3");
      ConnType = POP_CONN;
      break;
    case 143:
      strcpy(VchkpwLogName, "vchkpw-imap");
      ConnType = IMAP_CONN;
      break;
    case 465:
      strcpy(VchkpwLogName, "vchkpw-smtps");
      ConnType = SMTP_CONN;
      break;
    case 993:
      strcpy(VchkpwLogName, "vchkpw-imaps");
      ConnType = IMAP_CONN;
      break;
    case 995:
      strcpy(VchkpwLogName, "vchkpw-pop3s");
      ConnType = POP_CONN;
      break;
    default:
      strcpy(VchkpwLogName, "vchkpw-pop3");
      ConnType = POP_CONN;
      break;
  }


  /* read in the user name and password from file descriptor 3 */
  read_user_pass();

  if ( parse_email( TheName, TheUser, TheDomain, AUTH_SIZE) != 0 ) {
    snprintf(LogLine, sizeof(LogLine), 
      "%s: invalid user/domain characters %s:%s", 
      VchkpwLogName, TheName, IpAddr);

    vlog(VLOG_ERROR_PASSWD, TheUser, TheDomain, ThePass, 
                            TheName, IpAddr, LogLine);
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

#ifdef ENABLE_PASSWD
  /* if it is not in the virtual domains 
   * then check the user in /etc/passwd
   */
  } else if ( ENABLE_PASSWD == 1 ) {
    login_system_user();
#endif

  } else {
    snprintf(LogLine, sizeof(LogLine), "%s: vpopmail user not found %s@%s:%s", 
            VchkpwLogName, TheUser, TheDomain, IpAddr);
    vlog(VLOG_ERROR_LOGON, TheUser, TheDomain, ThePass, 
                           TheName, IpAddr, LogLine);
    vchkpw_exit(3);
  }
  vclose();

  /* The user is authenticated, now setup the environment */ 

  /* Set the programs effective group id */ 
  if ( ConnType != SMTP_CONN && setgid(pw_gid) == -1 ) {
    snprintf(LogLine, sizeof(LogLine), "%s: setgid %lu failed errno %d %s@%s:%s", 
      VchkpwLogName, (long unsigned)pw_gid, errno, TheUser, TheDomain, IpAddr);
    vlog(VLOG_ERROR_INTERNAL, TheUser, TheDomain, ThePass, 
                              TheName, IpAddr, LogLine);
    vchkpw_exit(4);
  }

  /* Set the programs effective user id */ 
  if ( ConnType != SMTP_CONN && setuid(pw_uid) == -1 ) {
    snprintf(LogLine, sizeof(LogLine), "%s: setuid %lu failed errno %d %s@%s:%s", 
      VchkpwLogName, (long unsigned)pw_uid, errno, TheUser, TheDomain, IpAddr);
    vlog(VLOG_ERROR_INTERNAL, TheUser, TheDomain, ThePass, 
                                TheName, IpAddr, LogLine);
    vchkpw_exit(5);
  }

  /* Change to the users Maildir directory 
   * don't do this for smtp authentication connections
   */
  if (ConnType != SMTP_CONN &&  chdir(pw_dir) == -1) {
    if ( vpw!=NULL) { 
      if ( vmake_maildir(TheDomain, vpw->pw_dir )!= VA_SUCCESS ) {
        snprintf(LogLine, sizeof(LogLine), 
          "%s: autocreate dir errno %d %s %s@%s:%s", 
          VchkpwLogName, errno, pw_dir, TheUser, TheDomain, IpAddr);
        vlog(VLOG_ERROR_INTERNAL, TheUser, TheDomain, ThePass, 
                                  TheName, IpAddr, LogLine);
        vchkpw_exit(6);
      }
      chdir(pw_dir);
    } else {
      snprintf(LogLine, sizeof(LogLine), "%s: chdir failed errno %d %s %s@%s:%s", 
        VchkpwLogName, errno, pw_dir, TheUser, TheDomain, IpAddr);
      vlog(VLOG_ERROR_INTERNAL, TheUser, TheDomain, ThePass, 
                                TheName, IpAddr, LogLine);
      vchkpw_exit(6);
    }
  }

  /* The the USER variable */
  snprintf (envbuf1, sizeof(envbuf1), "%s%s", VCHKPW_USER, TheUser);
  if ( putenv(envbuf1) == -1 ) {
    snprintf(LogLine, sizeof(LogLine), 
      "%s: putenv(USER) failed errno %d %s@%s:%s", 
      VchkpwLogName, errno, TheUser, TheDomain, IpAddr);
    vlog(VLOG_ERROR_INTERNAL, TheUser, TheDomain, ThePass, 
                              TheName, IpAddr, LogLine);
    vchkpw_exit(7);
  }

  /* Now HOME */
  snprintf (envbuf2, sizeof(envbuf2), "%s%s", VCHKPW_HOME, pw_dir);
  if ( putenv(envbuf2) == -1 ) {
    snprintf(LogLine, sizeof(LogLine), 
      "%s: putenv(HOME) failed errno %d %s@%s:%s", 
      VchkpwLogName, errno, TheUser, TheDomain, IpAddr);
    vlog(VLOG_ERROR_INTERNAL, TheUser, TheDomain, ThePass, 
                              TheName, IpAddr, LogLine);
    vchkpw_exit(8);
  }

  /* Now SHELL */
  strncpy(envbuf3,VCHKPW_SHELL,sizeof(envbuf3));
  envbuf3[sizeof(envbuf3)-1] = 0;   /* make sure it's NULL terminated */
  if ( putenv(envbuf3) == -1 ) {
    snprintf(LogLine, sizeof(LogLine), 
      "%s: putenv(SHELL) failed errno %d %s@%s:%s", 
      VchkpwLogName, errno, TheUser, TheDomain, IpAddr);
    vlog(VLOG_ERROR_INTERNAL, TheUser, TheDomain, ThePass, 
                              TheName, IpAddr, LogLine);
    vchkpw_exit(9);
  }

  /* Now VPOPUSER */
  snprintf (envbuf4, sizeof(envbuf4), "%s%s", VCHKPW_VPOPUSER, TheName);
  if ( putenv(envbuf4) == -1 ) {
    snprintf(LogLine, sizeof(LogLine),
      "%s: putenv(VPOPUSER) failed errno %d %s@%s:%s", 
      VchkpwLogName, errno, TheUser, TheDomain, IpAddr);
    vlog(VLOG_ERROR_INTERNAL, TheUser, TheDomain, ThePass, 
                              TheName, IpAddr, LogLine);
    vchkpw_exit(10);
  }

  /* close the log connection */
  if ( ENABLE_LOGGING > 0 ) closelog();

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
    if ( *ripper=='%' ) *ripper = '#';
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
      fprintf(stderr, "%s: vchkpw is only for talking with qmail-popup and qmail-pop3d. \
It is not for runnning on the command line.\n", VchkpwLogName);
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
    if ( l==i ) break;
  }

  /* parse out the password */
  memset(ThePass,0,AUTH_SIZE);
  for(j=0,++l;l<AUTH_INC_SIZE;++j,++l){
    ThePass[j] = TheDomain[l];
    if ( ThePass[j] == 0 ) break;
    if ( l==i ) break;
  }

  /* parse out the response */
  memset(TheResponse,0,AUTH_SIZE);
  for(j=0,++l;l<AUTH_INC_SIZE;++j,++l){
    TheResponse[j] = TheDomain[l];
    if ( TheResponse[j] == 0 ) break;
    if ( l==i ) break;
  }

  /* open the log if configured */
  if ( ENABLE_LOGGING > 0 ) {
    openlog(LOG_NAME,LOG_PID,LOG_MAIL);
  }

  if ( TheName[0] == 0 ) {
    snprintf(LogLine, sizeof(LogLine), "%s: null user name given %s:%s", 
      VchkpwLogName, TheName, IpAddr);
    vlog(VLOG_ERROR_LOGON, TheUser, TheDomain, ThePass, 
                           TheName, IpAddr, LogLine);
    vchkpw_exit(12);
  }

  if ( ThePass[0] == 0 ) {
    snprintf(LogLine, sizeof(LogLine), "%s: null password given %s:%s", 
      VchkpwLogName, TheName, IpAddr);
    vlog(VLOG_ERROR_PASSWD, TheUser, TheDomain, ThePass, 
                            TheName, IpAddr, LogLine);
    vchkpw_exit(13);
  }
}

void login_virtual_user()
{
  int apopaccepted = -1;
  int cramaccepted = -1;
  char AuthType[15] = "PLAIN";

  /* If thier directory path is empty make them a new one */
  if ( vpw->pw_dir == NULL || vpw->pw_dir[0]==0 ) {

    /* if making a new directory failed log the error and exit */
    if ( make_user_dir(vpw->pw_name, TheDomain, pw_uid, pw_gid)==NULL){
      snprintf(LogLine, sizeof(LogLine), "%s: dir auto create failed %s@%s:%s", 
        VchkpwLogName, TheUser, TheDomain, IpAddr);
      vlog(VLOG_ERROR_INTERNAL, TheUser, TheDomain, ThePass, 
                                TheName, IpAddr, LogLine);
      vchkpw_exit(14);
    }

  }

#ifdef CLEAR_PASS 
  /* Check CRAM-MD5 auth */
  if(ConnType == SMTP_CONN) {
	  /* printf("vchkpw: smtp auth\n"); */
    cramaccepted = authcram(ThePass,TheResponse,vpw->pw_clear_passwd);
    if(cramaccepted == 0) strcpy(AuthType, "CRAM-MD5");
  }

  /* Check APOP auth */
  if(ConnType == POP_CONN) {
    apopaccepted = authapop(ThePass,TheResponse,vpw->pw_clear_passwd);
    if(apopaccepted == 0) strcpy(AuthType, "APOP");
  }
#endif


#ifdef ENABLE_LEARN_PASSWORDS
  /* check for a valid vpopmail passwd field */
  if ( vpw->pw_passwd==NULL||vpw->pw_passwd[0]==0) {
    mkpasswd3(ThePass,TheCrypted, AUTH_SIZE);
    vpw->pw_passwd = TheCrypted;
    vpw->pw_clear_passwd = ThePass;
    vauth_setpw(vpw, TheDomain);
  }
#else
  if ( vpw->pw_passwd==NULL||vpw->pw_passwd[0]==0) {
    snprintf(LogLine, sizeof(LogLine), "%s: user has no password %s@%s:%s", 
      VchkpwLogName, TheUser, TheDomain, IpAddr);
    vlog(VLOG_ERROR_INTERNAL, TheUser, TheDomain, ThePass, 
                              TheName, IpAddr, LogLine);
    vchkpw_exit(15);
  }
#endif


  /* Encrypt the clear text password using the crypted 
   * password as the salt then
   * check if it matches the encrypted password 
   * If it does not match, log errors if requested and exit 
   */
  if ( (cramaccepted != 0 ) &&  (apopaccepted != 0 ) && 
       vauth_crypt(TheUser, TheDomain, ThePass, vpw) != 0 ) {

    if ( ENABLE_LOGGING==1||ENABLE_LOGGING==2){
      snprintf(LogLine, sizeof(LogLine), "%s: password fail %s@%s:%s",
        VchkpwLogName, TheUser, TheDomain, IpAddr);

    } else if ( ENABLE_LOGGING==3||ENABLE_LOGGING==4){
      snprintf(LogLine, sizeof(LogLine), "%s: password fail (pass: '%s') %s@%s:%s",
        VchkpwLogName, ThePass, TheUser, TheDomain, IpAddr);
    } else { 
      LogLine[0] = 0;
    }

    vlog( VLOG_ERROR_PASSWD, TheUser, TheDomain, ThePass, 
                             TheName, IpAddr, LogLine);
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

  struct vlimits limits;
  if (vget_limits (TheDomain, &limits)) {
    snprintf(LogLine, sizeof(LogLine), "%s: No default vlimits and no vlimits for domain %s found",
             VchkpwLogName, TheDomain);
    vlog(VLOG_ERROR_INTERNAL, TheUser, TheDomain, ThePass, TheName, IpAddr, LogLine);
    vchkpw_exit(1);
  }

  /* They are authenticated now, check for restrictions
   * Check if they are allowed pop access 
   */
  if ( ConnType == POP_CONN && vlimits_check_capability (vpw, &limits, NO_POP)) {
    snprintf(LogLine, sizeof(LogLine), "%s: pop access denied %s@%s:%s", 
             VchkpwLogName, TheUser, TheDomain, IpAddr);
    vlog(VLOG_ERROR_ACCESS, TheUser, TheDomain, ThePass, TheName, IpAddr, LogLine);
    vchkpw_exit(1);
  }
     /* Check if they are allowed smtp access 
      */
  else if ( ConnType == SMTP_CONN && vlimits_check_capability (vpw, &limits, NO_SMTP)) {
    snprintf(LogLine, sizeof(LogLine), "%s: smtp access denied %s@%s:%s", 
             VchkpwLogName, TheUser, TheDomain, IpAddr);
    vlog(VLOG_ERROR_ACCESS, TheUser, TheDomain, ThePass, TheName, IpAddr, LogLine);
    vchkpw_exit(1);
  }

    /* Check if they are allowed imap access
    */
  else if ( ConnType == IMAP_CONN && vlimits_check_capability (vpw, &limits, NO_IMAP)) {
    snprintf(LogLine, sizeof(LogLine), "%s: imap access denied %s@%s:%s",
             VchkpwLogName, TheUser, TheDomain, IpAddr);
    vlog(VLOG_ERROR_ACCESS, TheUser, TheDomain, ThePass, TheName, IpAddr, LogLine);
    vchkpw_exit(1);
  }
  /* show success but with no password */
  if ( ENABLE_LOGGING == 1 || ENABLE_LOGGING == 4) { 
    snprintf(LogLine, sizeof(LogLine), "%s: (%s) login success %s@%s:%s",
      VchkpwLogName, AuthType, TheUser, TheDomain, IpAddr);
    vlog(VLOG_AUTH, TheUser, TheDomain, ThePass, TheName, IpAddr, LogLine);
  }
  


  /* If authentication logging is enabled
   * update the authentication time on the account
   */
#ifdef ENABLE_AUTH_LOGGING
  vset_lastauth(TheUser,TheDomain,IpAddr);
#endif

#ifdef POP_AUTH_OPEN_RELAY
  /* Check if we should open up relay for this account
   * there is no need to open up relay for smtp authentication
   */ 
  if ( (vpw->pw_gid & NO_RELAY)==0 && LocalPort!=25 && LocalPort!=465 ) {
    open_smtp_relay();        
  }
#endif

  /* Save the directory pointer */
  pw_dir = vpw->pw_dir;

}

#ifdef ENABLE_PASSWD
void login_system_user()
{
#ifdef HAS_SHADOW
 struct spwd *spw;
#endif
 struct passwd *pw;

  if ((pw=getpwnam(TheUser)) == NULL ) {
    snprintf(LogLine, sizeof(LogLine), "%s: system user not found %s:%s", 
                      VchkpwLogName, TheUser, IpAddr);
    vlog(VLOG_ERROR_LOGON, TheUser, TheDomain, ThePass, 
                           TheName, IpAddr, LogLine);
    vchkpw_exit(21);
  }

#ifdef HAS_SHADOW
  if ((spw = getspnam(TheUser)) == NULL) {
    snprintf(LogLine, sizeof(LogLine), 
      "%s: system user shadow entry not found %s:%s", 
      VchkpwLogName, TheName, IpAddr);
    vlog(VLOG_ERROR_LOGON, TheUser, TheDomain, ThePass, 
                           TheName, IpAddr, LogLine);
    vchkpw_exit(22);
  }

  if ( strcmp(crypt(ThePass,spw->sp_pwdp),spw->sp_pwdp) != 0 ) {
#else
  if ( strcmp(crypt(ThePass,pw->pw_passwd),pw->pw_passwd) != 0 ) {
#endif
    if (ENABLE_LOGGING==1||ENABLE_LOGGING==2) {
      snprintf(LogLine, sizeof(LogLine), "%s: system password fail %s:%s", 
        VchkpwLogName, TheName, IpAddr);

    } else if (ENABLE_LOGGING==3||ENABLE_LOGGING==4) {
      snprintf(LogLine, sizeof(LogLine),
        "%s: system password fail (pass: '%s') %s:%s",
        VchkpwLogName, ThePass, TheName, IpAddr);

    } else { 
      LogLine[0] = 0;
    }

    vlog(VLOG_ERROR_PASSWD, TheUser, TheDomain, ThePass, 
                            TheName, IpAddr, LogLine);
    vchkpw_exit(23);
  }
   pw_uid = pw->pw_uid;
   pw_gid = pw->pw_gid;
   pw_dir = pw->pw_dir;
   
   /* show success but with no password */
   if ( ENABLE_LOGGING == 1 || ENABLE_LOGGING == 4) {
     snprintf(LogLine, sizeof(LogLine),
       "%s: system password login success %s:%s",
       VchkpwLogName, TheUser, IpAddr);
     vlog(VLOG_AUTH, TheUser, TheDomain, ThePass, TheName, IpAddr, LogLine);
   }

#ifdef POP_AUTH_OPEN_RELAY
   if ( LocalPort != 25 && LocalPort != 465 ) {
        open_smtp_relay();    
    }
#endif

}
#endif

void vchkpw_exit(int err)
{
  if ( ENABLE_LOGGING > 0 ) closelog();
  vclose();
  exit(err);
}

/* log messages and figure out what type they are and where 
 * they should go depending on configure options 
 * any one of the pointers can be null, i.e. the information is not available 
 * messages are autmatically cleaned for syslog if it is necessary 
 */
void vlog(int verror, char *TheUser, char *TheDomain, char *ThePass, 
                      char *TheName, char *IpAddr, char *LogLine) 
{

  /* always log to syslog if enabled */
  if ( (verror == VLOG_ERROR_PASSWD) && 
       ( ENABLE_LOGGING==1 || ENABLE_LOGGING==2 || ENABLE_LOGGING==3 || 
         ENABLE_LOGGING==4 ) ) {
    syslog(LOG_NOTICE,sysc(LogLine));

  } else if ( verror == VLOG_ERROR_INTERNAL ) {
    syslog(LOG_NOTICE, sysc(LogLine));

  } else if ( verror == VLOG_ERROR_LOGON ) {
    syslog(LOG_NOTICE, sysc(LogLine));

  } else if ( verror == VLOG_ERROR_ACCESS ) {
    syslog(LOG_NOTICE, sysc(LogLine));

  } else if ( verror == VLOG_AUTH && 
            ( ENABLE_LOGGING == 1 || ENABLE_LOGGING == 4 ) ) {
    syslog(LOG_NOTICE, sysc(LogLine));
  }

#ifdef ENABLE_MYSQL_LOGGING
  /* always log to mysql if mysql logging is enabled and it 
   * is not internal error 
   */

  if ( (verror == VLOG_ERROR_PASSWD) && ( ENABLE_LOGGING==1 || ENABLE_LOGGING==2 || ENABLE_LOGGING==3 || ENABLE_LOGGING==4 ) ) {
      if ( (logmysql(verror, TheUser, TheDomain, ThePass, TheName, IpAddr, LogLine) ) != 0 ) {
          syslog(LOG_NOTICE,"vchkpw: can't write MySQL logs");
      }
  } else if ( verror == VLOG_ERROR_INTERNAL ) {
      if ( (logmysql(verror, TheUser, TheDomain, ThePass, TheName, IpAddr, LogLine) ) != 0 ) {
        syslog(LOG_NOTICE,"vchkpw: can't write MySQL logs");
      }
  } else if ( verror == VLOG_ERROR_LOGON ) {
      if ( (logmysql(verror, TheUser, TheDomain, ThePass, TheName, IpAddr, LogLine) ) != 0 ) {
        syslog(LOG_NOTICE,"vchkpw: can't write MySQL logs");
      }
  } else if ( verror == VLOG_ERROR_ACCESS ) {
      if ( (logmysql(verror, TheUser, TheDomain, ThePass, TheName, IpAddr, LogLine) ) != 0 ) {
        syslog(LOG_NOTICE,"vchkpw: can't write MySQL logs");
      }
  } else if ( verror == VLOG_AUTH && ( ENABLE_LOGGING == 1 || ENABLE_LOGGING == 4 ) ) {
      if ( (logmysql(verror, TheUser, TheDomain, ThePass, TheName, IpAddr, LogLine) ) != 0 ) {
        syslog(LOG_NOTICE,"vchkpw: can't write MySQL logs");
      }
  }
#endif
}

int authcram(unsigned char *challenge, unsigned char *response, unsigned char *password)
{
   unsigned char digest[16];
   unsigned char digascii[33];
   unsigned char h;
   int j;

   hmac_md5( challenge, strlen(challenge), password, strlen(password), digest);

   digascii[32]=0;
   
   for (j=0;j<16;j++)
   {
     h=digest[j] >> 4;
     digascii[2*j]=hextab[h];
     h=digest[j] & 0x0f;
     digascii[(2*j)+1]=hextab[h];
   }   
   /* printf("digascii: %s, response: %s", digascii, response); */
   return(strcmp(digascii,response));
}

int authapop(unsigned char *password, unsigned char *timestamp, unsigned char *clearpass)
{
#ifdef USE_ACTIVE_DIR
  return(-1);
#else
  MD5_CTX context;
  unsigned char digest[16];
  char encrypted[16*2+1];
  char *s;
  int i;
 
  MD5Init(&context);
  MD5Update(&context, timestamp, strlen(timestamp));
  MD5Update(&context, clearpass, strlen(clearpass));
  MD5Final(digest, &context);
  s = encrypted;
  for (i = 0; i < sizeof(digest); ++i) {
    *s = hextab[digest[i]/16]; ++s;
    *s = hextab[digest[i]%16]; ++s;
  }
  *s = '\0';
 
  return strcmp(password,encrypted);
#endif
}
