/*
 * Copyright (C) 2004 Inter7 Internet Technologies, Inc.
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
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include "config.h"
#include "vpopmail.h"
#include "vauth.h"
#include "vlimits.h"

/* two responses */
#define RET_OK "+OK \r\n"
#define RET_OK_MORE "+OK+\r\n"
#define RET_ERR "-ERR "
#define RET_CRLF "\r\n"

#define READ_TIMEOUT 60
#define MAX_TMP_BUFF 1024
#define MAX_FILE_NAME 156

#define TOKENS " \n\t\r"
#define PASS_TOKENS "\n\r"
#define PARAM_TOKENS " =:\n\r"
#define GECOS_TOKENS "=:\n\r"
#define LIST_DOMAIN_TOKENS " :\t\n\r"


#define INVALID_DIRECTORY RET_ERR "XXX invaild directory" RET_CRLF

char ReadBuf[MAX_TMP_BUFF];
char WriteBuf[MAX_TMP_BUFF];
char SystemBuf[MAX_TMP_BUFF];
struct vqpasswd *tmpvpw;

struct vqpasswd  AuthVpw;

#define AUTH_SIZE 156
char TheUser[AUTH_SIZE];
char ThePass[AUTH_SIZE];        /* for C/R this is 'TheResponse' */
char TheDomain[AUTH_SIZE];
char TheDomainDir[256];
char TheUserDir[256];
char TheVpopmailDomains[256];

char TmpUser[AUTH_SIZE];
char TmpPass[AUTH_SIZE];        /* for C/R this is 'TheResponse' */
char TmpDomain[AUTH_SIZE];

#define LOGIN_LIMIT 3
int login_tries = 0; /* count invalid login attempts */
int logged_in = 0;   /* 0=not logged in, 1=mailbox, 2=domain, 3=system */
int output_type = 0; /* 0=full, 1=compact, 2=silent */

int login();
int add_user();
int del_user();
int mod_user();
int user_info();
int add_domain();
int add_alias_domain();
int del_domain();
int dom_info();
int mk_dir();
int rm_dir();
int list_dir();
int rm_file();
int write_file();
int read_file();
int list_domains();
int find_domain();
int domain_count();
int user_count();
int list_users();
int list_alias();
int list_lists();
int get_ip_map();
int add_ip_map();
int del_ip_map();
int show_ip_map();
int get_limits();
int set_limits();
int del_limits();
int get_lastauth();
int add_list();
int del_list();
int mod_list();
int quit();
int help();

/* utility functions */
void send_user_info(struct vqpasswd *tmpvpw);
char *validate_path(char *path);
int bkscandir(const char *dirname,
              struct dirent ***namelist,
            int (*select)(struct dirent *),
            int (*compar)(const void *, const void *));
int qa_sort(const void * a, const void * b);

#define DEC    ( int *(*)() )


typedef struct func_t {
 int level; /* user level required to run the command */
 char *command;
 int (*func)();
 char *help;
} func_t;

/*
{"login", login, "user@domain password<crlf>" },
*/

func_t Functions[] = {
{2, "add_user", add_user, "user@domain password<crlf>" },
{2, "del_user", del_user, "user@domain<crlf>" },
{1, "mod_user", mod_user, "user@domain (option lines)<crlf>.<crlf>" },
{2, "user_info", user_info, "user_domain<crlf>" },
{3, "add_alias_domain", add_alias_domain, "domain alias<crlf>" },
{3, "add_domain", add_domain, "domain postmaster@password<crlf>" },
{3, "del_domain", del_domain, "domain<crlf>" },
{3, "dom_info", dom_info, "domain<crlf>" },
{1, "mk_dir", mk_dir, "/full/path/to/dir<crlf>" },
{1, "rm_dir", rm_dir, "/full/path/to/dir<crlf>" },
{1, "list_dir", list_dir, "/full/path/to/dir<crlf>" },
{1, "rm_file", rm_file, "/full/path/to/file<crlf>" },
{1, "write_file", write_file, "/full/path (data lines)<crlf>.<crlf>" },
{1, "read_file", read_file, "/full/path<crlf>" },
{3, "list_domains", list_domains, "[page per_page]<crlf>" },
{3, "find_domain", find_domain, "domain [per-page]<crlf>" },
{3, "domain_count", domain_count, "<crlf>" },
{2, "user_count", user_count, "domain<crlf>" },
{2, "list_users", list_users, "domain [page per_page]<crlf>" },
{2, "list_alias", list_alias, "domain<crlf>" },
{2, "list_lists", list_lists, "domain<crlf>" },
{1, "get_ip_map", get_ip_map, "domain<crlf>" },
{3, "add_ip_map", add_ip_map, "domain ip<crlf>" },
{3, "del_ip_map", del_ip_map, "domain<crlf>" },
{3, "show_ip_map", show_ip_map, "domain<crlf>" },
{2, "get_limits", get_limits, "domain<crlf>" },
{3, "set_limits", set_limits, "domain (option lines)<crlf>.<crlf>"},
{3, "del_limits", del_limits, "domain<crlf>" },
{1, "get_lastauth", get_lastauth, "user@domain<crlf>" },
{2, "add_list", add_list, "domain listname (command line options)<crlf>" },
{2, "del_list", del_list, "domain listname<crlf>"},
{2, "mod_list", mod_list, "domain listname (command line options)<crlf>" },
{0, "help", help, "help" },
{0, "quit", quit, "quit" },
{0, NULL, NULL, NULL } };


int wait_read()
{
 struct timeval tv;
 fd_set rfds;
 /*int read_size;*/

  tv.tv_sec = READ_TIMEOUT;
  tv.tv_usec = 0;

  FD_ZERO(&rfds);
  FD_SET(1,&rfds);

  memset(ReadBuf,0,sizeof(ReadBuf));
  if (select(2,&rfds,(fd_set *) 0,(fd_set *)0,&tv)>=1) {
    fgets(ReadBuf,sizeof(ReadBuf),stdin);
    return(1);
  }
  return(-1);
}

int wait_write()
{
 struct timeval tv;
 fd_set wfds;
 int write_size;

  tv.tv_sec = READ_TIMEOUT;
  tv.tv_usec = 0;

  FD_ZERO(&wfds);
  FD_SET(1,&wfds);

  if (select(2,(fd_set*)0, &wfds,(fd_set *)0,&tv)>=1) {
    if ( (write_size = fputs(WriteBuf,stdout) < 0) ) exit(-1);
    if ( fflush(stdout)!=0) exit(-2);
    return(write_size);
  }
  return(-1);
}


int main(int argc, char **argv)
{
 int read_size;
 char *command;
 int i;
 int found;

  if( vauth_open( 1 )) {
      snprintf(WriteBuf,sizeof(WriteBuf),
        RET_ERR "599 Can't open authentication database." RET_CRLF);
      wait_write();
    exit( -1 );
  }

  snprintf(WriteBuf,sizeof(WriteBuf), RET_OK);
  wait_write();

  /* authenticate first */
  while( ! logged_in ) {
    read_size = wait_read();
    if ( read_size < 0 ) {
      snprintf(WriteBuf,sizeof(WriteBuf), 
        RET_ERR "XXX read timeout" RET_CRLF);
      wait_write();
      exit(-1);
    } 

    i=login() ;
    if ( i == -2 ) {
      login_tries ++;
      if (login_tries >= LOGIN_LIMIT) {
        snprintf(WriteBuf, sizeof(WriteBuf), 
          RET_ERR "112 excessive invalid logins, goodbye" RET_CRLF);
        wait_write();
        vclose();
        exit(-1);
      }
    }
    wait_write();
  }

  while(1) {
    read_size = wait_read();
    if ( read_size < 0 ) {
      snprintf(WriteBuf,sizeof(WriteBuf), 
        RET_ERR "XXX read timeout" RET_CRLF);
      wait_write();
      vclose();
      exit(-1);
    } 
    if ((command=strtok(ReadBuf,TOKENS))==NULL) {
      snprintf(WriteBuf,sizeof(WriteBuf),
        RET_ERR "XXX Invalid command" RET_CRLF);
      wait_write();
      continue;
    }

    for(found=0,i=0;found==0&&Functions[i].command!=NULL;++i ) {
      if (    ( ! strcasecmp(Functions[i].command, command) )
           && ( logged_in >= Functions[i].level ) ) { 
        found = 1;
        Functions[i].func();
      }
    }
    if ( found == 0 ) {
      snprintf(WriteBuf, sizeof(WriteBuf), 
        RET_ERR "XXX Invalid command " RET_CRLF);
    }
    wait_write();
  }
}

int login()
{
 char *command;
 char *email;
 char *pass;
 /* not used?
 char *param; */
 uid_t uid;
 gid_t gid;


  if ((command=strtok(ReadBuf,TOKENS))==NULL) {
    snprintf(WriteBuf, sizeof(WriteBuf), 
      RET_ERR "XXX authorization first" RET_CRLF);
    return(-1);
  }

  if (!strcasecmp(command,"quit")) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_OK );
    wait_write();
    vclose();
    exit(-1);
  }

  if (!strcasecmp(command,"help")) { help(); return(-1); }

  if (!strcasecmp(command,"login")) { output_type = 0 ; }
  else if (!strcasecmp(command,"clogin")) { output_type = 1 ; }
  else if (!strcasecmp(command,"slogin")) { output_type = 2 ; }
  else {
    snprintf(WriteBuf, sizeof(WriteBuf), 
      RET_ERR "XXX authorization first" RET_CRLF);
    return(-1);
  }

  if ((email=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf, sizeof(WriteBuf), 
      RET_ERR "XXX email address required" RET_CRLF);
    return(-1);
  }

  if ((pass=strtok(NULL,PASS_TOKENS))==NULL) {
    snprintf(WriteBuf, sizeof(WriteBuf), 
      RET_ERR "XXX password required" RET_CRLF);
    return(-1);
  }

  if ( parse_email( email, TheUser, TheDomain, AUTH_SIZE) != 0 ) {
    snprintf(WriteBuf, sizeof(WriteBuf), 
      RET_ERR "112 invalid login" RET_CRLF);
    return(-2); 
  }

  if ((tmpvpw = vauth_getpw(TheUser, TheDomain))==NULL) {
    snprintf(WriteBuf, sizeof(WriteBuf), 
      RET_ERR "112 invalid login" RET_CRLF);
    return(-2);
  }

  if ( vauth_crypt(TheUser, TheDomain, pass, tmpvpw) != 0 ) {
    snprintf(WriteBuf, sizeof(WriteBuf), 
     RET_ERR "112 invalid login" RET_CRLF);
    return(-2);
  } 

  AuthVpw.pw_name = strdup(tmpvpw->pw_name);
  AuthVpw.pw_passwd = strdup(tmpvpw->pw_passwd);
  AuthVpw.pw_uid = tmpvpw->pw_uid;
  AuthVpw.pw_gid = tmpvpw->pw_gid;
  AuthVpw.pw_flags = tmpvpw->pw_flags;
  AuthVpw.pw_gecos = strdup(tmpvpw->pw_gecos);
  AuthVpw.pw_dir = strdup(tmpvpw->pw_dir);
  AuthVpw.pw_shell = strdup(tmpvpw->pw_shell);
  AuthVpw.pw_clear_passwd = strdup(tmpvpw->pw_clear_passwd);

  snprintf( TheUserDir, sizeof(TheUserDir), AuthVpw.pw_dir);
  snprintf( TheDomainDir, sizeof(TheDomainDir), 
    vget_assign(TheDomain,NULL,0,&uid,&gid));
  snprintf(TheVpopmailDomains, sizeof(TheVpopmailDomains), "%s/domains", 
    VPOPMAILDIR);

  if ( AuthVpw.pw_gid & SA_ADMIN )
    logged_in = 3;
  else if ( (AuthVpw.pw_gid & QA_ADMIN) || 
              (strcmp("postmaster", AuthVpw.pw_name)==0) ) {
    AuthVpw.pw_gid |= QA_ADMIN; 
    strcpy( TheDomainDir, vget_assign(TheDomain,NULL,0,NULL,NULL));
    logged_in = 2;
  }
  else
    logged_in = 1;

  if(output_type < 2 ) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_OK_MORE);
    wait_write();

    snprintf(WriteBuf,sizeof(WriteBuf), "vpopmail_dir %s" RET_CRLF, VPOPMAILDIR);
    wait_write();

    snprintf(WriteBuf,sizeof(WriteBuf), "domain_dir %s" RET_CRLF, TheDomainDir);
    wait_write();

    snprintf(WriteBuf,sizeof(WriteBuf), "uid %d" RET_CRLF, uid);
    wait_write();

    snprintf(WriteBuf,sizeof(WriteBuf), "gid %d" RET_CRLF, gid);
    wait_write();

    send_user_info(&AuthVpw);

    snprintf(WriteBuf, sizeof(WriteBuf), "." RET_CRLF);
  }
  else
    snprintf(WriteBuf,sizeof(WriteBuf), RET_OK);

  return(0);
}

int add_user()
{
 char *email_address;
 char *password;
 int   ret;

  if ( !(AuthVpw.pw_gid & QA_ADMIN) && !(AuthVpw.pw_gid & SA_ADMIN) ) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX not authorized" RET_CRLF);
    return(-1);
  }

  if ((email_address=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX email_address required" RET_CRLF);
    return(-1);
  }

  if ( parse_email( email_address, TmpUser, TmpDomain, AUTH_SIZE) != 0 ) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX invaild email addrress" RET_CRLF);
    return(-1);
  } 

  if (!(AuthVpw.pw_gid&SA_ADMIN) && (AuthVpw.pw_gid&QA_ADMIN) && 
       (strcmp(TheDomain,TmpDomain))!=0 ) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX not authorized for domain" RET_CRLF);
    return(-1);
  }

  if ((password=strtok(NULL,PASS_TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX password required" RET_CRLF);
    return(-1);
  }

  snprintf(WriteBuf,sizeof(WriteBuf), RET_OK);
  if ((ret=vadduser(TmpUser, TmpDomain, password, TmpUser, USE_POP )) < 0 ) {
    snprintf(WriteBuf,sizeof(WriteBuf),RET_ERR "XXX %s" RET_CRLF, verror(ret));
    return(-1);
  }
  return(0);
}

int del_user()
{
 char *email_address;
 int   ret;

  if ( !(AuthVpw.pw_gid & QA_ADMIN) && !(AuthVpw.pw_gid & SA_ADMIN) ) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX not authorized" RET_CRLF);
    return(-1);
  }

  if ((email_address=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX email_address required" RET_CRLF);
    return(-1);
  }

  if ( parse_email( email_address, TmpUser, TmpDomain, AUTH_SIZE) != 0 ) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX invaild email addrress" RET_CRLF);
    return(-1);
  } 

  if (!(AuthVpw.pw_gid&SA_ADMIN) && (AuthVpw.pw_gid&QA_ADMIN) && 
       (strcmp(TheDomain,TmpDomain))!=0 ) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX not authorized for domain" RET_CRLF);
    return(-1);
  }

  if ((ret=vdeluser(TmpUser, TmpDomain)) != VA_SUCCESS ) {
    snprintf(WriteBuf,sizeof(WriteBuf),RET_ERR "XXX %s" RET_CRLF, verror(ret));
    return(-1);
  }

  snprintf(WriteBuf,sizeof(WriteBuf), RET_OK);
  return(0);
}

int mod_user()
{
 char Crypted[64];
 char *email_address;
 char *param;
 char *value;
 int   ret;
 int   is_user = 0;
 int   can_override = 0;

  if ((email_address=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX email_address required" RET_CRLF );
    return(-1);
  }

  if ( parse_email( email_address, TmpUser, TmpDomain, AUTH_SIZE) != 0 ) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX invaild email addrress" RET_CRLF);
    return(-1);
  } 

  /* domain administrator */
  if (!(AuthVpw.pw_gid&SA_ADMIN) && (AuthVpw.pw_gid&QA_ADMIN)) { 

    /* if not their domain, reject */
    if ( strcmp(TheDomain,TmpDomain)!= 0 )  {
      snprintf(WriteBuf,sizeof(WriteBuf),
        RET_ERR "XXX not authorized for domain" RET_CRLF);
      return(-1);
    } 

  /* user, not system admin */
  } else if ( !(AuthVpw.pw_gid&SA_ADMIN) ) {

    /* set the is_user flag to decide which things they can change */
    is_user = 1;

    /* if not their account, reject */
    if ( strcmp(TheDomain,TmpDomain)!= 0 || strcmp(TheUser,TmpUser)!= 0 )  {
      snprintf(WriteBuf,sizeof(WriteBuf),
        RET_ERR "XXX not authorized for domain" RET_CRLF);
      return(-1);
    }
  }
  /* else they have to be a system admin */


  /* get the current user information */
  if ((tmpvpw = vauth_getpw(TmpUser, TmpDomain))==NULL) {
    snprintf(WriteBuf, sizeof(WriteBuf), 
      RET_ERR "XXX user does not exist" RET_CRLF);
    while(fgets(ReadBuf,sizeof(ReadBuf),stdin)!=NULL && 
          strcmp(ReadBuf, ".\n") != 0 );
    return(-1);
  }

  if ( AuthVpw.pw_gid & SA_ADMIN || 
       (AuthVpw.pw_gid & QA_ADMIN && AuthVpw.pw_gid & V_OVERRIDE) ) {
    can_override = 1;
  }
  

  while(fgets(ReadBuf,sizeof(ReadBuf),stdin)!=NULL ) {
    if ( ReadBuf[0]  == '.' ) break;
    if ( (param = strtok(ReadBuf,PARAM_TOKENS)) == NULL ) continue;
    if ( (value = strtok(NULL,PASS_TOKENS)) == NULL ) continue;

    /* anyone can change the comment field */
    if ( strcmp(param,"comment") == 0 ) {
      tmpvpw->pw_gecos = strdup(value);

    } else if ( can_override==1 && strcmp(param,"quota") == 0 ) {
      tmpvpw->pw_shell = format_maildirquota(strdup(value));
      update_maildirsize(TmpDomain, tmpvpw->pw_dir, tmpvpw->pw_shell);

    /* anyone can change encrypted password? */
    } else if ( strcmp(param,"encrypted_password") == 0 ) {
      tmpvpw->pw_passwd = strdup(value);

    /* anyone can change clear text password, 
     * must set encrypted pass too
     */
    } else if ( strcmp(param,"clear_text_password") == 0  &&
                !(tmpvpw->pw_flags & NO_PASSWD_CHNG) ) {
      tmpvpw->pw_clear_passwd = strdup(value);
      mkpasswd3(value,Crypted, sizeof(Crypted));
      tmpvpw->pw_passwd = Crypted;
 
    /* only system admins or domain admins with override can clear all flags */
    } else if ( can_override==1 && strcmp(param,"clear_all_flags") == 0 ) {
      tmpvpw->pw_gid = 0; 

    } else if ( can_override==1 && strcmp(param,"no_password_change") == 0 ) {
      if ( atoi(value) == 1 ) tmpvpw->pw_gid |= NO_PASSWD_CHNG;
      else if ( atoi(value) == 0 ) tmpvpw->pw_gid &= ~NO_PASSWD_CHNG;

    } else if ( can_override==1 && strcmp(param,"no_pop") == 0 ) {
      if ( atoi(value) == 1 ) tmpvpw->pw_gid |= NO_POP;
      else if ( atoi(value) == 0 ) tmpvpw->pw_gid &= ~NO_POP;

    } else if ( can_override==1 && strcmp(param,"no_webmail") == 0 ) {
      if ( atoi(value) == 1 )  tmpvpw->pw_gid |= NO_WEBMAIL;
      else if ( atoi(value) == 0 ) tmpvpw->pw_gid &= ~NO_WEBMAIL;

    } else if ( can_override==1 && strcmp(param,"no_imap") == 0 ) {
      if ( atoi(value) == 1 ) tmpvpw->pw_gid |= NO_IMAP;
      else if ( atoi(value) == 0 ) tmpvpw->pw_gid &= ~NO_IMAP;

    } else if ( can_override==1 && strcmp(param,"bounce_mail") == 0 ) {
      if ( atoi(value) == 1 ) tmpvpw->pw_gid |= BOUNCE_MAIL;
      else if ( atoi(value) == 0 ) tmpvpw->pw_gid &= ~BOUNCE_MAIL;

    } else if ( can_override==1 && strcmp(param,"no_relay") == 0 ) {
      if ( atoi(value) == 1 ) tmpvpw->pw_gid |= NO_RELAY;
      else if ( atoi(value) == 0 ) tmpvpw->pw_gid &= ~NO_RELAY;

    } else if ( can_override==1 && strcmp(param,"no_dialup") == 0 ) {
      if ( atoi(value) == 1 ) tmpvpw->pw_gid |= NO_DIALUP;
      else if ( atoi(value) == 0 ) tmpvpw->pw_gid &= ~NO_DIALUP;

    } else if ( can_override==1 && strcmp(param,"user_flag_0") == 0 ) {
      if ( atoi(value) == 1 ) tmpvpw->pw_gid |= V_USER0;
      else if ( atoi(value) == 0 ) tmpvpw->pw_gid &= ~V_USER0;

    } else if ( can_override==1 && strcmp(param,"user_flag_1") == 0 ) {
      if ( atoi(value) == 1 ) tmpvpw->pw_gid |= V_USER1;
      else if ( atoi(value) == 0 ) tmpvpw->pw_gid &= ~V_USER1;

    } else if ( strcmp(param,"user_flag_2") == 0 ) {
      if ( atoi(value) == 1 ) tmpvpw->pw_gid |= V_USER2;
      else if ( atoi(value) == 0 ) tmpvpw->pw_gid &= ~V_USER2;

    } else if ( strcmp(param,"user_flag_3") == 0 ) {
      if ( atoi(value) == 1 )  tmpvpw->pw_gid |= V_USER3;
      else if ( atoi(value) == 0 ) tmpvpw->pw_gid &= ~V_USER3;

    } else if ( can_override==1 && strcmp(param,"no_smtp") == 0 ) {
      if ( atoi(value) == 1 ) tmpvpw->pw_gid |= NO_SMTP;
      else if ( atoi(value) == 0 ) tmpvpw->pw_gid &= ~NO_SMTP;

    } else if ( AuthVpw.pw_gid & SA_ADMIN && 
                strcmp(param,"system_admin_privileges") == 0 ) {
      if ( atoi(value) == 1 ) tmpvpw->pw_gid |= SA_ADMIN;
      else if ( atoi(value) == 0 ) tmpvpw->pw_gid &= ~SA_ADMIN;

    } else if ( AuthVpw.pw_gid & SA_ADMIN && 
                strcmp(param,"system_expert_privileges") == 0 ) {
      if ( atoi(value) == 1 ) tmpvpw->pw_gid |= SA_EXPERT;
      else if ( atoi(value) == 0 ) tmpvpw->pw_gid &= ~SA_EXPERT;

    } else if ( (AuthVpw.pw_gid & SA_ADMIN || AuthVpw.pw_gid & QA_ADMIN) &&
                 strcmp(param,"domain_admin_privileges") == 0 ) {
      if ( atoi(value) == 1 ) tmpvpw->pw_gid |= QA_ADMIN;
      else if ( atoi(value) == 0 ) tmpvpw->pw_gid &= ~QA_ADMIN;

    } else if ( AuthVpw.pw_gid & SA_ADMIN && 
                strcmp(param,"override_domain_limits") == 0 ) {
      if ( atoi(value) == 1 ) tmpvpw->pw_gid |= V_OVERRIDE;
      else if ( atoi(value) == 0 ) tmpvpw->pw_gid &= ~V_OVERRIDE;

    } else if ( strcmp(param,"no_spamassassin") == 0 ) {
      if ( atoi(value) == 1 ) {
        tmpvpw->pw_gid |= NO_SPAMASSASSIN;
      } else if ( atoi(value) == 0 ) {
        tmpvpw->pw_gid &= ~NO_SPAMASSASSIN;
      }
    } else if ( strcmp(param,"delete_spam") == 0 ) {
      if ( atoi(value) == 1 ) {
        tmpvpw->pw_gid |= DELETE_SPAM;
      } else if ( atoi(value) == 0 ) {
        tmpvpw->pw_gid &= ~DELETE_SPAM;
      }
    }
  }

  if ( (ret=vauth_setpw( tmpvpw, TmpDomain )) != 0 ) {
    snprintf(WriteBuf,sizeof(WriteBuf),RET_ERR "XXX %s" RET_CRLF, verror(ret)); 
  } else {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_OK);
  }

  return(0);
}

int user_info()
{
 char *email_address;

  if ( !(AuthVpw.pw_gid & QA_ADMIN) && !(AuthVpw.pw_gid & SA_ADMIN) ) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX not authorized" RET_CRLF);
    return(-1);
  }

  if ((email_address=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX email_address required" RET_CRLF);
    return(-1);
  }

  if ( parse_email( email_address, TmpUser, TmpDomain, AUTH_SIZE) != 0 ) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX invaild email addrress" RET_CRLF);
    return(-1);
  } 

  if (!(AuthVpw.pw_gid&SA_ADMIN) && (AuthVpw.pw_gid&QA_ADMIN) && 
       (strcmp(TheDomain,TmpDomain))!=0 ) {
    snprintf(WriteBuf, sizeof(WriteBuf), 
      RET_ERR "XXX not authorized for domain" RET_CRLF);
    return(-1);
  }

  if ((tmpvpw = vauth_getpw(TmpUser, TmpDomain))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX user does not exist" RET_CRLF);
    return(-1);
  } 

  snprintf(WriteBuf,sizeof(WriteBuf), RET_OK_MORE);
  wait_write();

  send_user_info(tmpvpw);
  snprintf(WriteBuf, sizeof(WriteBuf), "." RET_CRLF);
  return(0);

}

void send_user_info(struct vqpasswd *tmpvpw)
{

  snprintf(WriteBuf,sizeof(WriteBuf),"name %s" RET_CRLF, tmpvpw->pw_name);
  wait_write();

  snprintf(WriteBuf,sizeof(WriteBuf),"comment %s" RET_CRLF, tmpvpw->pw_gecos);
  wait_write();

  snprintf(WriteBuf,sizeof(WriteBuf),"quota %s" RET_CRLF, tmpvpw->pw_shell);
  wait_write();

  snprintf(WriteBuf,sizeof(WriteBuf),"user_dir %s" RET_CRLF, tmpvpw->pw_dir);
  wait_write();


  snprintf(WriteBuf,sizeof(WriteBuf),"encrypted_password %s" RET_CRLF, 
    tmpvpw->pw_passwd);
  wait_write();

  snprintf(WriteBuf,sizeof(WriteBuf),"clear_text_password %s" RET_CRLF, 
    tmpvpw->pw_clear_passwd);
  wait_write();

  if( output_type ) {
    snprintf(WriteBuf, sizeof(WriteBuf), "gidflags %i" RET_CRLF, tmpvpw->pw_gid);
    wait_write();

  } else {

    if ( tmpvpw->pw_gid & NO_PASSWD_CHNG ) {
      snprintf(WriteBuf, sizeof(WriteBuf), "no_password_change 1" RET_CRLF);
    } else {
      snprintf(WriteBuf, sizeof(WriteBuf), "no_password_change 0" RET_CRLF);
    }
    wait_write();

    if ( tmpvpw->pw_gid & NO_POP ) {
      snprintf(WriteBuf, sizeof(WriteBuf), "no_pop 1" RET_CRLF);
    } else {
      snprintf(WriteBuf, sizeof(WriteBuf), "no_pop 0" RET_CRLF);
    }
    wait_write();

    if ( tmpvpw->pw_gid & NO_WEBMAIL ) {
      snprintf(WriteBuf, sizeof(WriteBuf), "no_webmail 1" RET_CRLF);
    } else {
      snprintf(WriteBuf, sizeof(WriteBuf), "no_webmail 0" RET_CRLF);
    }
    wait_write();

    if ( tmpvpw->pw_gid & NO_IMAP ) {
      snprintf(WriteBuf, sizeof(WriteBuf), "no_imap 1" RET_CRLF);
    } else {
      snprintf(WriteBuf, sizeof(WriteBuf), "no_imap 0" RET_CRLF);
    }
    wait_write();

    if ( tmpvpw->pw_gid & BOUNCE_MAIL ) {
      snprintf(WriteBuf, sizeof(WriteBuf), "bounce_mail 1" RET_CRLF);
    } else {
      snprintf(WriteBuf, sizeof(WriteBuf), "bounce_mail 0" RET_CRLF);
    }
    wait_write();
    if ( tmpvpw->pw_gid & NO_RELAY ) {
      snprintf(WriteBuf, sizeof(WriteBuf), "no_relay 1" RET_CRLF);
    } else {
      snprintf(WriteBuf, sizeof(WriteBuf), "no_relay 0" RET_CRLF);
    }
    wait_write();
    if ( tmpvpw->pw_gid & NO_DIALUP ) {
      snprintf(WriteBuf, sizeof(WriteBuf), "no_dialup 1" RET_CRLF);
    } else {
      snprintf(WriteBuf, sizeof(WriteBuf), "no_dialup 0" RET_CRLF);
    }
    wait_write();
    if ( tmpvpw->pw_gid & V_USER0 ) {
      snprintf(WriteBuf, sizeof(WriteBuf), "user_flag_0 1" RET_CRLF);
    } else {
      snprintf(WriteBuf, sizeof(WriteBuf), "user_flag_0 0" RET_CRLF);
    }
    wait_write();
    if ( tmpvpw->pw_gid & V_USER1 ) {
      snprintf(WriteBuf, sizeof(WriteBuf), "user_flag_1 1" RET_CRLF);
    } else {
      snprintf(WriteBuf, sizeof(WriteBuf), "user_flag_1 0" RET_CRLF);
    }
    wait_write();
    if ( tmpvpw->pw_gid & V_USER2 ) {
      snprintf(WriteBuf, sizeof(WriteBuf), "user_flag_2 1" RET_CRLF);
    } else {
      snprintf(WriteBuf, sizeof(WriteBuf), "user_flag_2 0" RET_CRLF);
    }
    wait_write();
    if ( tmpvpw->pw_gid & V_USER3 ) {
      snprintf(WriteBuf, sizeof(WriteBuf), "user_flag_3 1" RET_CRLF);
    } else {
      snprintf(WriteBuf, sizeof(WriteBuf), "user_flag_3 0" RET_CRLF);
    }
    wait_write();
    if ( tmpvpw->pw_gid & NO_SMTP ) {
      snprintf(WriteBuf, sizeof(WriteBuf), "no_smtp 1" RET_CRLF);
    } else {
      snprintf(WriteBuf, sizeof(WriteBuf), "no_smtp 0" RET_CRLF);
    }
    wait_write();
    if ( tmpvpw->pw_gid & QA_ADMIN ) {
      snprintf(WriteBuf, sizeof(WriteBuf), "domain_admin_privileges 1" RET_CRLF);
    } else {
      snprintf(WriteBuf, sizeof(WriteBuf), "domain_admin_privileges 0" RET_CRLF);
    }
    wait_write();
    if ( tmpvpw->pw_gid & V_OVERRIDE ) {
      snprintf(WriteBuf, sizeof(WriteBuf), "override_domain_limits 1" RET_CRLF);
    } else {
      snprintf(WriteBuf, sizeof(WriteBuf), "override_domain_limits 0" RET_CRLF);
    }
    wait_write();
    if ( tmpvpw->pw_gid & NO_SPAMASSASSIN ) {
      snprintf(WriteBuf, sizeof(WriteBuf), "no_spamassassin 1" RET_CRLF);
    } else {
      snprintf(WriteBuf, sizeof(WriteBuf), "no_spamassassin 0" RET_CRLF);
    }
    wait_write();
    if ( tmpvpw->pw_gid & DELETE_SPAM ) {
      snprintf(WriteBuf, sizeof(WriteBuf), "delete_spam 1" RET_CRLF);
    } else {
      snprintf(WriteBuf, sizeof(WriteBuf), "delete_spam 0" RET_CRLF);
    }
    wait_write();
    if ( tmpvpw->pw_gid & SA_ADMIN ) {
      snprintf(WriteBuf, sizeof(WriteBuf), "system_admin_privileges 1" RET_CRLF);
    } else {
      snprintf(WriteBuf, sizeof(WriteBuf), "system_admin_privileges 0" RET_CRLF);
    }
    wait_write();
  }
  snprintf(WriteBuf, sizeof(WriteBuf), "." RET_CRLF);

}

int add_domain()
{
 char *domain;
 char *password;
 int   ret;

  if ( !(AuthVpw.pw_gid & SA_ADMIN) ) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX not authorized" RET_CRLF);
    return(-1);
  }

  if ((domain=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX domain required" RET_CRLF);
    return(-1);
  }

  if ((password=strtok(NULL,PASS_TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX password required" RET_CRLF);
    return(-1);
  }

  if ((ret=vadddomain(domain,VPOPMAILDIR,VPOPMAILUID,VPOPMAILGID))!=VA_SUCCESS){
    snprintf(WriteBuf,sizeof(WriteBuf),RET_ERR "XXX %s" RET_CRLF, verror(ret));
    return(-1);
  }

  if ((ret=vadduser("postmaster",domain , password, "postmaster", USE_POP ))<0){
    snprintf(WriteBuf,sizeof(WriteBuf),RET_ERR "XXX %s" RET_CRLF, verror(ret));
    return(-1);
  }

  snprintf(WriteBuf,sizeof(WriteBuf), RET_OK);
  return(0);
}

/*
 *
 *  Consider adding code from vaddaliasdomain program so it doesn't 
 *  matter which way you enter the parameters, it always does the
 *  right thing.
 *
 */

int add_alias_domain()
{
 char *domain;
 char *alias;
 int   ret;

  if ( !(AuthVpw.pw_gid & SA_ADMIN) ) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX not authorized" RET_CRLF);
    return(-1);
  }

  if ((domain=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX domain required" RET_CRLF);
    return(-1);
  }

  if ((alias=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX alias name required" RET_CRLF);
    return(-1);
  }

  if ((ret=vaddaliasdomain(alias,domain))!=VA_SUCCESS){
    snprintf(WriteBuf,sizeof(WriteBuf),RET_ERR "XXX %s" RET_CRLF, 
             verror(ret));
    return(-1);
  }

  snprintf(WriteBuf,sizeof(WriteBuf), RET_OK);
  return(0);
}

int del_domain()
{
 char *domain;
 char *dummy="";
 int   ret;

  if ( !(AuthVpw.pw_gid & SA_ADMIN) ) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX not authorized" RET_CRLF);
    return(-1);
  }

  if ((domain=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX domain required" RET_CRLF);
    return(-1);
  }

  if ((ret=vdeldomain(domain))!=VA_SUCCESS){
    snprintf(WriteBuf,sizeof(WriteBuf),RET_ERR "XXX %s" RET_CRLF, verror(ret));
    return(-1);
  }

  /*  Clear the domain info cache  */
  vget_assign(dummy, NULL, 0, NULL, NULL );

  snprintf(WriteBuf,sizeof(WriteBuf), RET_OK);
  return(0);
}

int dom_info()
{
 char *domain;
 domain_entry *entry;
 char *aliases[MAX_DOM_ALIAS];
 int  i, aliascount=0;

  if ( !(AuthVpw.pw_gid & SA_ADMIN) ) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX not authorized" RET_CRLF);
    return(-1);
  }

  if ((domain=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX domain required" RET_CRLF);
    return(-1);
  }

  entry = get_domain_entries( domain );

  if (entry==NULL) {   //  something went wrong
    if( verrori ) {    //  could not open file
      snprintf(WriteBuf,sizeof(WriteBuf),RET_ERR "100 %s" RET_CRLF, 
               verror(verrori));
      return(0);
    } else {           //  domain does not exist
      snprintf(WriteBuf,sizeof(WriteBuf),RET_ERR "101 %s" RET_CRLF, 
               verror(VA_DOMAIN_DOES_NOT_EXIST));
      return(0);
    }
  }

  snprintf(WriteBuf,sizeof(WriteBuf), RET_OK_MORE);
  wait_write();

  while( entry ) {
    if (strcmp(entry->domain, entry->realdomain) != 0) {
      aliases[aliascount++] = strdup(entry->domain);

    } else {
      snprintf(WriteBuf,sizeof(WriteBuf),"domain %s" RET_CRLF, 
               entry->domain);
      wait_write();
 
      snprintf(WriteBuf,sizeof(WriteBuf),"path %s" RET_CRLF, 
               entry->path);
      wait_write();

      snprintf(WriteBuf,sizeof(WriteBuf),"uid %i" RET_CRLF, 
               entry->uid);
      wait_write();

      snprintf(WriteBuf,sizeof(WriteBuf),"gid %i" RET_CRLF, 
               entry->gid);
      wait_write();

    }

    entry = get_domain_entries(NULL);
  }

  for(i=0;i<aliascount;i++) {
    snprintf(WriteBuf,sizeof(WriteBuf),"alias %s" RET_CRLF, 
             aliases[i]);
    wait_write();
    free( aliases[i] );
  } 



  snprintf(WriteBuf, sizeof(WriteBuf), "." RET_CRLF);
  return(0);
}

char *validate_path(char *path)
{
 static char newpath[256];
 static char theemail[256];
 static char theuser[256];
 static char thedomain[256];
 static char thedir[256];
 struct vqpasswd *myvpw;
 int   i;
 char *slash;
 char *atsign;

  memset(newpath,0,256);
  memset(theemail,0,256);
  memset(theuser,0,256);
  memset(thedomain,0,256);
  memset(thedir,0,256);

  /* check for fake out path */
  if ( strstr(path,"..") != NULL ) {
    snprintf(WriteBuf,sizeof(WriteBuf), INVALID_DIRECTORY);
    return(NULL);
  }

  /* check for fake out path */
  if ( strstr(path,"%") != NULL ) {
    snprintf(WriteBuf,sizeof(WriteBuf), INVALID_DIRECTORY);
    return(NULL);
  }

  /* expand the path */
  if ( path[0] == '/' ) {
    snprintf(newpath,sizeof(newpath), path);
  } else { 
    slash = strchr( path, '/');
    if ( slash == NULL ) {
      snprintf(WriteBuf,sizeof(WriteBuf), INVALID_DIRECTORY);
      return(NULL);
    }
    atsign = strchr(path,'@');

    /* possible email address */
    if ( atsign != NULL ) {
      if ( atsign > slash ) {
        snprintf(WriteBuf,sizeof(WriteBuf), INVALID_DIRECTORY);
        return(NULL);
      }
      for(i=0;path[i]!='/'&&path[i]!=0&&i<256;++i) {
        theemail[i] = path[i];
      }
      theemail[i] = 0;

      if ( parse_email( theemail, theuser, thedomain, 256) != 0 ) {
        snprintf(WriteBuf,sizeof(WriteBuf), INVALID_DIRECTORY);
        return(NULL);
      } 

      if ((myvpw = vauth_getpw(theuser, thedomain))==NULL) {
        snprintf(WriteBuf,sizeof(WriteBuf), INVALID_DIRECTORY);
        return(NULL);
      }


      /* limit domain admins to their domains */
      if ( AuthVpw.pw_gid & QA_ADMIN ) {
        if ( strncmp(TheDomain,thedomain,strlen(TheDomain))!=0 ) {
          snprintf(WriteBuf,sizeof(WriteBuf), INVALID_DIRECTORY);
          return(NULL);
        }

      /* limit users to their accounts */
      } else if ( !(AuthVpw.pw_gid&SA_ADMIN) ){
        if ( strcmp(TheUser, theuser) != 0 || 
             strcmp(TheDomain, thedomain) != 0 ) {
          snprintf(WriteBuf,sizeof(WriteBuf), INVALID_DIRECTORY);
          return(NULL);
        }
      }
      snprintf(newpath, sizeof(newpath), myvpw->pw_dir);
      strncat(newpath,&path[i],sizeof(newpath));
    } else {
      for(i=0;path[i]!='/'&&path[i]!=0&&i<256;++i) {
        thedomain[i] = path[i];
      }
      thedomain[i] = 0;
      if ( vget_assign(thedomain, thedir,sizeof(thedir),NULL,NULL) == NULL ) {
        snprintf(WriteBuf,sizeof(WriteBuf), INVALID_DIRECTORY);
        return(NULL);
      } 
      snprintf(newpath,sizeof(newpath), thedir);
      strncat(newpath,&path[i],sizeof(newpath));
    }
  }

  if ( AuthVpw.pw_gid & SA_ADMIN ) { 
    if ( strncmp(TheVpopmailDomains,newpath,strlen(TheVpopmailDomains))!=0 ) {
      snprintf(WriteBuf,sizeof(WriteBuf), 
        RET_ERR "XXX unauthorized directory" RET_CRLF);
      return(NULL);
    }
  } else if ( AuthVpw.pw_gid & QA_ADMIN ) {
    if ( strncmp(TheDomainDir,newpath,strlen(TheDomainDir)) !=0 ) {
      snprintf(WriteBuf,sizeof(WriteBuf), 
        RET_ERR "XXX unauthorized directory" RET_CRLF);
      return(NULL);
    }
  } else {
    if ( strncmp(TheUserDir,newpath,strlen(TheUserDir))!=0 ) {
      snprintf(WriteBuf,sizeof(WriteBuf), 
        RET_ERR "XXX unauthorized directory" RET_CRLF);
      return(NULL);
    }
  }
  return(newpath);
}

int mk_dir()
{
 char *dir;

  /* must supply directory parameter */
  if ((dir=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX directory required" RET_CRLF);
    return(-1);
  }

  if ( (dir=validate_path(dir)) == NULL ) return(-1);

 
  /* make directory, return error */  
  if ( mkdir(dir,0700) < 0 ) {
    snprintf(WriteBuf,sizeof(WriteBuf),RET_ERR "XXX %s" RET_CRLF, 
      strerror(errno));
    return(-1);
  }

  /* Change ownership */
  if ( chown(dir,VPOPMAILUID,VPOPMAILGID) == -1 ) {
    snprintf(WriteBuf,sizeof(WriteBuf),RET_ERR "XXX %s" RET_CRLF, 
      strerror(errno));
    return(-1);
  }

  snprintf(WriteBuf,sizeof(WriteBuf), RET_OK);
  return(0);
}

int rm_dir()
{
 char *dir;

  /* must supply directory parameter */
  if ((dir=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX directory required" RET_CRLF);
    return(-1);
  }

  if ( (dir=validate_path(dir)) == NULL ) return(-1);

  /* recursive directory delete */ 
  if ( vdelfiles(dir) < 0 ) {
    snprintf(WriteBuf,sizeof(WriteBuf),RET_ERR "XXX %s" RET_CRLF, 
      strerror(errno));
    return(-1);
  }
  snprintf(WriteBuf,sizeof(WriteBuf), RET_OK);
  return(0);
}

int list_dir()
{
 char *dir;
 DIR *mydir;
 struct dirent *mydirent;
 struct stat statbuf;

  /* must supply directory parameter */
  if ((dir=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX directory required" RET_CRLF);
    return(-1);
  }

  if ( (dir=validate_path(dir)) == NULL ) return(-1);

  if ( chdir(dir) < 0 ) {
    snprintf(WriteBuf,sizeof(WriteBuf),RET_ERR "XXX %s" RET_CRLF, 
      strerror(errno));
    return(-1);
  }

  if ( (mydir = opendir(".")) == NULL ) {
    snprintf(WriteBuf,sizeof(WriteBuf),RET_ERR "XXX %s" RET_CRLF, 
      strerror(errno));
    return(-1);
  }

  snprintf(WriteBuf,sizeof(WriteBuf), RET_OK_MORE);
  wait_write();

  while((mydirent=readdir(mydir))!=NULL){

    /* skip the current directory and the parent directory entries */
    if ( strncmp(mydirent->d_name,".", 2) ==0 || 
         strncmp(mydirent->d_name,"..", 3)==0 ) continue;
   
    if ( lstat(mydirent->d_name,&statbuf) < 0 ) {
      printf("error on stat of %s\n", mydirent->d_name);
      exit(-1);
    }
    snprintf( WriteBuf, sizeof(WriteBuf), mydirent->d_name);
    if ( S_ISREG(statbuf.st_mode ) ) {
      strncat(WriteBuf," file", sizeof(WriteBuf));
    } else if ( S_ISDIR(statbuf.st_mode ) ) {
      strncat(WriteBuf," dir", sizeof(WriteBuf));
    } else if ( S_ISCHR(statbuf.st_mode ) ) {
      strncat(WriteBuf," chardev", sizeof(WriteBuf));
    } else if ( S_ISBLK(statbuf.st_mode ) ) {
      strncat(WriteBuf," blkdev", sizeof(WriteBuf));
    } else if ( S_ISFIFO(statbuf.st_mode ) ) {
      strncat(WriteBuf," fifo", sizeof(WriteBuf));
    } else if ( S_ISLNK(statbuf.st_mode ) ) {
      strncat(WriteBuf," link", sizeof(WriteBuf));
    } else if ( S_ISSOCK(statbuf.st_mode ) ) {
      strncat(WriteBuf," sock", sizeof(WriteBuf));
    } else {
      strncat(WriteBuf," unknown", sizeof(WriteBuf));
    }
    strncat(WriteBuf,RET_CRLF, sizeof(WriteBuf));
    wait_write();
  }
  if ( closedir(mydir) < 0 ) {
    /* oh well, at least we might die soon */
  }

  snprintf(WriteBuf, sizeof(WriteBuf), "." RET_CRLF);
  return(0);
}

int rm_file()
{
 char *filename;


  /* must supply directory parameter */
  if ((filename=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX filename required" RET_CRLF);
    return(-1);
  }

  if ( (filename=validate_path(filename)) == NULL ) return(-1);

  /* unlink filename */ 
  if ( unlink(filename) < 0 ) {
    snprintf(WriteBuf,sizeof(WriteBuf),RET_ERR "XXX %s" RET_CRLF, 
      strerror(errno));
    return(-1);
  }

  snprintf(WriteBuf,sizeof(WriteBuf), RET_OK);
  return(0);
}

int write_file()
{
 char *filename;
 FILE *fs;
 static char tmpbuf[1024];

  /* must supply directory parameter */
  if ((filename=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX filename required" RET_CRLF);
    return(-1);
  }

  if ( (filename=validate_path(filename)) == NULL ) return(-1);

  if ( (fs=fopen(filename,"w+"))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf),RET_ERR "XXX %s" RET_CRLF, 
      strerror(errno));
    return(-1);
  }

  while( fgets(tmpbuf,sizeof(tmpbuf),stdin)!=NULL && 
         strcmp(tmpbuf, "." RET_CRLF)!=0 && 
         strcmp(tmpbuf, ".\n")!= 0 ) { 
     
    fputs(tmpbuf,fs);
  }
  fclose(fs);

  snprintf(WriteBuf,sizeof(WriteBuf), RET_OK);
  return(0);
}

int read_file()
{
 char *filename;
 FILE *fs;
 static char tmpbuf[1024];

  /* must supply directory parameter */
  if ((filename=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX filename required" RET_CRLF);
    return(-1);
  }

  if ( (filename=validate_path(filename)) == NULL ) return(-1);

  if ( (fs=fopen(filename,"r"))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf),RET_ERR "XXX %s" RET_CRLF, 
      strerror(errno));
    return(-1);
  }

  snprintf(WriteBuf,sizeof(WriteBuf), RET_OK_MORE);
  wait_write();

  while(fgets(tmpbuf,sizeof(tmpbuf),fs)!=NULL){
    if ( strcmp(tmpbuf, "." RET_CRLF) == 0 || strcmp(tmpbuf, ".\n") == 0 ) {
      snprintf(WriteBuf, sizeof(WriteBuf), ".");
      strncat(WriteBuf, tmpbuf, sizeof(WriteBuf));
    } else {
      memcpy(WriteBuf,tmpbuf,sizeof(tmpbuf));
    }
    wait_write();
  }
  fclose(fs);

  if ( tmpbuf[0] != 0 && tmpbuf[strlen(tmpbuf)-1] != '\n' ) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_CRLF "." RET_CRLF);
  } else {
    snprintf(WriteBuf,sizeof(WriteBuf), "." RET_CRLF);
  }
  return(0);
}
int list_domains()
{
 domain_entry *entry;
 char *tmpstr;
 int page = 0;
 int lines_per_page = 0;
 int count;
 int start;
 int end;

  if ( !(AuthVpw.pw_gid & SA_ADMIN) ) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX not authorized" RET_CRLF);
    return(-1);
  }

  if ((tmpstr=strtok(NULL,TOKENS))!=NULL) {
    page = atoi(tmpstr);
    if ( page < 0 ) page = 0;
    if ((tmpstr=strtok(NULL,TOKENS))!=NULL) {
      lines_per_page = atoi(tmpstr);
      if ( lines_per_page < 0 ) lines_per_page = 0;
    }
  }
  if ( page > 0 && lines_per_page > 0 ) {
    start = (page-1) * lines_per_page;
    end   = page * lines_per_page;
  } else {
    start = 0;
    end = 0;
  }


  entry=get_domain_entries( "" );
  if ( entry == NULL ) {
    snprintf(WriteBuf, sizeof(WriteBuf), 
      RET_ERR "XXX could not open assign file" RET_CRLF);
    return(-1);
  }

  snprintf(WriteBuf,sizeof(WriteBuf), RET_OK_MORE);
  wait_write();

  count = 0;
  while( entry ) {
    if ( end>0 ) {
      if ( count>=start && count<end ) {
        snprintf(WriteBuf,sizeof(WriteBuf), "%s %s" RET_CRLF, 
          entry->realdomain, entry->domain);
        wait_write();
      } else if ( count>=end ) {
        break;
      }
    } else { 
      snprintf(WriteBuf,sizeof(WriteBuf), "%s %s" RET_CRLF, 
        entry->realdomain, entry->domain);
      wait_write();
    }
    ++count;
    entry=get_domain_entries(NULL);
    
  }
  snprintf(WriteBuf,sizeof(WriteBuf), "." RET_CRLF);
  return(0);
}
int find_domain()
{
 domain_entry *entry;
 char *tmpstr;
 char *domain;
 int miss;
 int count;
 int page;
 int per_page;

  per_page = 0;
 
  if ( !(AuthVpw.pw_gid & SA_ADMIN) ) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX not authorized" RET_CRLF);
    return(-1);
  }

  if ((domain=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX domain required" RET_CRLF);
    return(-1);
  }

  if ((tmpstr=strtok(NULL,TOKENS))!=NULL) {
    per_page = atoi(tmpstr);
  }

  entry=get_domain_entries( "" );
  if ( entry == NULL ) {
    snprintf(WriteBuf, sizeof(WriteBuf), 
      RET_ERR "XXX could not open assign file" RET_CRLF);
    return(-1);
  }

  snprintf(WriteBuf,sizeof(WriteBuf), RET_OK_MORE);
  wait_write();

  count = 0;
  miss  = 1;

  while( entry ) {
    if( strcmp(domain, entry->domain)==0 ) {
      miss = 0; 
      break;
    }
    count++;

    entry=get_domain_entries(NULL);
    
  }

  if( miss ) {
    page = 0;
  } else if( per_page > 0 ) {
    page = ( count / per_page ) + 1;
  } else {
    page = count;
  }

  snprintf(WriteBuf,sizeof(WriteBuf), "page %i" RET_CRLF, page );
  wait_write();

  snprintf(WriteBuf,sizeof(WriteBuf), "." RET_CRLF);
  return(0);
}

int domain_count()
{
 domain_entry *entry;
 int count;

  if ( !(AuthVpw.pw_gid & SA_ADMIN) ) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX not authorized" RET_CRLF);
    return(-1);
  }


  entry=get_domain_entries( "" );
  if ( entry == NULL ) {
    snprintf(WriteBuf, sizeof(WriteBuf), 
      RET_ERR "XXX could not open assign file" RET_CRLF);
    return(-1);
  }

  snprintf(WriteBuf,sizeof(WriteBuf), RET_OK_MORE);
  wait_write();

  count = 0;
  while( entry ) {
    ++count;
    entry=get_domain_entries(NULL);
    
  }
  snprintf(WriteBuf,sizeof(WriteBuf), "count %i" RET_CRLF, count);
  wait_write();

  snprintf(WriteBuf,sizeof(WriteBuf), "." RET_CRLF);
  return(0);
}

int user_count()
{
 char *domain;
 int first;
 int count;

  if ( !(AuthVpw.pw_gid & QA_ADMIN) && !(AuthVpw.pw_gid & SA_ADMIN) ) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX not authorized" RET_CRLF);
    return(-1);
  }

  if ((domain=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX email_address required" RET_CRLF);
    return(-1);
  }

  if ( !(AuthVpw.pw_gid&SA_ADMIN) && (AuthVpw.pw_gid&QA_ADMIN) && 
        (strcmp(TheDomain,domain))!=0 ) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX not authorized for domain" RET_CRLF);
    return(-1);
  }

  if ( !(AuthVpw.pw_gid&SA_ADMIN) && (AuthVpw.pw_gid&QA_ADMIN) && 
        (strcmp(TheDomain,domain))!=0 ) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX not authorized for domain" RET_CRLF);
    return(-1);
  }

  snprintf(WriteBuf, sizeof(WriteBuf), RET_OK_MORE);
  wait_write();

  first=1;
  count = 0;
  while((tmpvpw=vauth_getall(domain, first, 1))!=NULL) {
    first = 0;
    ++count;
  }
  snprintf(WriteBuf,sizeof(WriteBuf), "count %i" RET_CRLF, count);
  wait_write();
  snprintf(WriteBuf,sizeof(WriteBuf), "." RET_CRLF);
  return(0);
}


int list_users()
{
 char *domain;
 char *tmpstr;
 int first;
 int page = 0;
 int lines_per_page = 0;
 int count;
 int start;
 int end;

  if ( !(AuthVpw.pw_gid & QA_ADMIN) && !(AuthVpw.pw_gid & SA_ADMIN) ) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX not authorized" RET_CRLF);
    return(-1);
  }

  if ((domain=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX email_address required" RET_CRLF);
    return(-1);
  }

  if ( !(AuthVpw.pw_gid&SA_ADMIN) && (AuthVpw.pw_gid&QA_ADMIN) && 
        (strcmp(TheDomain,domain))!=0 ) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX not authorized for domain" RET_CRLF);
    return(-1);
  }

  if ((tmpstr=strtok(NULL,TOKENS))!=NULL) {
    page = atoi(tmpstr);
    if ( page < 0 ) page = 0;
    if ((tmpstr=strtok(NULL,TOKENS))!=NULL) {
      lines_per_page = atoi(tmpstr);
      if ( lines_per_page < 0 ) lines_per_page = 0;
    }
  }
  if ( page > 0 && lines_per_page > 0 ) {
    start = (page-1) * lines_per_page;
    end   = page * lines_per_page;
  } else {
    start = 0;
    end = 0;
  }

  if ( !(AuthVpw.pw_gid&SA_ADMIN) && (AuthVpw.pw_gid&QA_ADMIN) && 
        (strcmp(TheDomain,domain))!=0 ) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX not authorized for domain" RET_CRLF);
    return(-1);
  }

  snprintf(WriteBuf, sizeof(WriteBuf), RET_OK_MORE);
  wait_write();

  first=1;
  count = 0;
  while((tmpvpw=vauth_getall(domain, first, 1))!=NULL) {
    first = 0;
    if ( end>0 ) {
      if ( count>=start && count<end ) {
        send_user_info(tmpvpw);
      } else if ( count>=end ) {
        break;
      }
    } else { 
      send_user_info(tmpvpw);
    }
    ++count;
  }
  snprintf(WriteBuf,sizeof(WriteBuf), "." RET_CRLF);
  return(0);
}

/*
 *
 *  This needs to be changed to use the new valias code
 *
 */

int list_alias()
{
 static char thedir[256];
 char *domain;
 char *tmpstr;
 int page = 0;
 int lines_per_page = 0;
 int count;
 int start;
 int end;
 int i,j;
 struct dirent **namelist;
 struct dirent *mydirent;

  if ( !(AuthVpw.pw_gid & QA_ADMIN) && !(AuthVpw.pw_gid & SA_ADMIN) ) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX not authorized" RET_CRLF);
    return(-1);
  }

  if ((domain=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX Domain required" RET_CRLF);
    return(-1);
  }

  if ( (vget_assign(domain,thedir,sizeof(thedir),NULL,NULL)) == NULL ) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX Invalid domain" RET_CRLF);
    return(-1);
  }

  if ((tmpstr=strtok(NULL,TOKENS))!=NULL) {
    page = atoi(tmpstr);
    if ( page < 0 ) page = 0;
    if ((tmpstr=strtok(NULL,TOKENS))!=NULL) {
      lines_per_page = atoi(tmpstr);
      if ( lines_per_page < 0 ) lines_per_page = 0;
    }
  }
  if ( page > 0 && lines_per_page > 0 ) {
    start = (page-1) * lines_per_page;
    end   = page * lines_per_page;
  } else {
    start = 0;
    end = 0;
  }

  if ( chdir(thedir) < 0 ) {
    snprintf(WriteBuf,sizeof(WriteBuf),RET_ERR "XXX %s" RET_CRLF, 
      strerror(errno));
    return(-1);
  }

  snprintf(WriteBuf, sizeof(WriteBuf), RET_OK_MORE);
  wait_write();

  j = bkscandir(".", &namelist, 0, qa_sort);

  count = 0;
  for(i=0;i<j;++i) {
    mydirent=namelist[i];

    if ( strncmp( ".qmail-", mydirent->d_name,7)!= 0 ) continue; 
    if ( strstr(mydirent->d_name, "-owner") != NULL ) continue;
    if ( strstr(mydirent->d_name, "-default") != NULL ) continue;

    if ( end>0 ) {
      if ( count>=start && count<end ) {
        snprintf(WriteBuf,sizeof(WriteBuf), "%s" RET_CRLF, mydirent->d_name);
        wait_write();
      } else if ( count>=end ) {
        break;
      }
    } else { 
      snprintf(WriteBuf,sizeof(WriteBuf), "%s" RET_CRLF, mydirent->d_name);
      wait_write();
    }
    ++count;
  }
  snprintf(WriteBuf,sizeof(WriteBuf), "." RET_CRLF);
  return(0);
}

int list_lists()
{
 static char thedir[256];
 char *domain;
 char *tmpstr;
 int page = 0;
 int lines_per_page = 0;
 int count;
 int start;
 int end;
 int i,j;
 struct dirent **namelist;
 struct dirent *mydirent;
 FILE *fs;
 static char tmpbuf[1024];

  if ( !(AuthVpw.pw_gid & QA_ADMIN) && !(AuthVpw.pw_gid & SA_ADMIN) ) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX not authorized" RET_CRLF);
    return(-1);
  }

  if ((domain=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX email_address required" RET_CRLF);
    return(-1);
  }

  if ( !(AuthVpw.pw_gid&SA_ADMIN) && (AuthVpw.pw_gid&QA_ADMIN) && 
        (strcmp(TheDomain,domain))!=0 ) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX not authorized for domain" RET_CRLF);
    return(-1);
  }

  if ( (vget_assign(domain,thedir,sizeof(thedir),NULL,NULL)) == NULL ) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX not authorized for domain" RET_CRLF);
    return(-1);
  }

  if ((tmpstr=strtok(NULL,TOKENS))!=NULL) {
    page = atoi(tmpstr);
    if ( page < 0 ) page = 0;
    if ((tmpstr=strtok(NULL,TOKENS))!=NULL) {
      lines_per_page = atoi(tmpstr);
      if ( lines_per_page < 0 ) lines_per_page = 0;
    }
  }
  if ( page > 0 && lines_per_page > 0 ) {
    start = (page-1) * lines_per_page;
    end   = page * lines_per_page;
  } else {
    start = 0;
    end = 0;
  }

  if ( chdir(thedir) < 0 ) {
    snprintf(WriteBuf,sizeof(WriteBuf),RET_ERR "XXX %s" RET_CRLF, 
      strerror(errno));
    return(-1);
  }

  snprintf(WriteBuf, sizeof(WriteBuf), RET_OK_MORE);
  wait_write();

  j = bkscandir(".", &namelist, 0, qa_sort);

  count = 0;
  for(i=0;i<j;++i) {
    mydirent=namelist[i];

    if ( strncmp( ".qmail-", mydirent->d_name,7)!= 0 ) continue;

    if ( (fs=fopen(mydirent->d_name,"r"))==NULL ) continue;
    fgets(tmpbuf,sizeof(tmpbuf),fs);
    fclose(fs);
    if ( strstr(tmpbuf, "ezmlm-reject") == 0 ) continue;

    if ( end>0 ) {
      if ( count>=start && count<end ) {
        snprintf(WriteBuf,sizeof(WriteBuf), "%s" RET_CRLF, mydirent->d_name);
        wait_write();
      } else if ( count>=end ) {
        break;
      }
    } else { 
      snprintf(WriteBuf,sizeof(WriteBuf), "%s" RET_CRLF, mydirent->d_name);
      wait_write();
    }
    ++count;
  }
  snprintf(WriteBuf,sizeof(WriteBuf), "." RET_CRLF);
  return(0);
}


int get_ip_map()
{
#ifdef IP_ALIAS_DOMAINS
 char *ip;
 static char  tmpdomain[256];

  if ( !(AuthVpw.pw_gid & SA_ADMIN) ) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX not authorized" RET_CRLF);
    return(-1);
  }

  if ((ip=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX ip required" RET_CRLF);
    return(-1);
  }

  if ( vget_ip_map(ip,tmpdomain,sizeof(tmpdomain)) < 0 ) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX error" RET_CRLF);
    return(-1);
  }

  snprintf(WriteBuf,sizeof(WriteBuf),RET_OK_MORE);
  wait_write();
 
  snprintf(WriteBuf,sizeof(WriteBuf),"%s %s" RET_CRLF, ip, tmpdomain);
  wait_write();
  snprintf(WriteBuf,sizeof(WriteBuf), "." RET_CRLF);

#else
  snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX not available" RET_CRLF);
#endif
  
  return(0);
}

int add_ip_map()
{
#ifdef IP_ALIAS_DOMAINS
 char *ip;
 char *domain;

  if ( !(AuthVpw.pw_gid & SA_ADMIN) ) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX not authorized" RET_CRLF);
    return(-1);
  }

  if ((ip=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX ip required" RET_CRLF);
    return(-1);
  }

  if ((domain=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX domain required" RET_CRLF);
    return(-1);
  }

  if ( vget_assign(domain, NULL,0,NULL,NULL) == NULL ) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX invalid domain" RET_CRLF);
    return(-1);
  }

  if ( vadd_ip_map(ip,domain) < 0 ) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX error" RET_CRLF);
    return(-1);
  }

  snprintf(WriteBuf,sizeof(WriteBuf),RET_OK);
#else
  snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX not available" RET_CRLF);
#endif
  return(0);
}

int del_ip_map()
{
#ifdef IP_ALIAS_DOMAINS
 char *ip;
 char *domain;

  if ( !(AuthVpw.pw_gid & SA_ADMIN) ) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX not authorized" RET_CRLF);
    return(-1);
  }

  if ((ip=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX ip required" RET_CRLF);
    return(-1);
  }

  if ((domain=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX domain required" RET_CRLF);
    return(-1);
  }

  if ( vdel_ip_map(ip,domain) < 0 ) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX error" RET_CRLF);
    return(-1);
  }

  snprintf(WriteBuf,sizeof(WriteBuf),RET_OK);

#else
  snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX not available" RET_CRLF);
#endif
  return(0);
}

int show_ip_map()
{
#ifdef IP_ALIAS_DOMAINS
 int first;
 static char r_ip[256];
 static char r_domain[256];

  if ( !(AuthVpw.pw_gid & SA_ADMIN) ) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX not authorized" RET_CRLF);
    return(-1);
  }

  snprintf(WriteBuf,sizeof(WriteBuf), RET_OK_MORE);
  wait_write();

  first = 1;
  while( vshow_ip_map(first,r_ip,r_domain) > 0 ) {
    first = 0;

    snprintf(WriteBuf, sizeof(WriteBuf), "%s %s" RET_CRLF, r_ip, r_domain);
    wait_write();
  }
  snprintf(WriteBuf,sizeof(WriteBuf), "." RET_CRLF);

#else
  snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX not available" RET_CRLF);
#endif
  return(0);
}

int get_limits()
{
 char *domain;
 int   ret;
 struct vlimits mylimits;

  if ( !(AuthVpw.pw_gid & SA_ADMIN) ) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX not authorized" RET_CRLF);
    return(-1);
  }

  if ((domain=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX domain required" RET_CRLF);
    return(-1);
  }

  if ((ret=vget_limits(domain,&mylimits))!=0){
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX could not get limits" RET_CRLF);
    return(-1);
  }

  snprintf(WriteBuf,sizeof(WriteBuf), RET_OK_MORE);
  wait_write();

  snprintf(WriteBuf,sizeof(WriteBuf), "max_popaccounts %d" RET_CRLF, 
    mylimits.maxpopaccounts); wait_write();
  snprintf(WriteBuf,sizeof(WriteBuf), "max_aliases %d" RET_CRLF, 
    mylimits.maxaliases); wait_write();
  snprintf(WriteBuf,sizeof(WriteBuf), "max_forwards %d" RET_CRLF, 
    mylimits.maxforwards); wait_write();
  snprintf(WriteBuf,sizeof(WriteBuf), "max_autoresponders %d" RET_CRLF, 
    mylimits.maxautoresponders); wait_write();
  snprintf(WriteBuf,sizeof(WriteBuf), "max_mailinglists %d" RET_CRLF, 
    mylimits.maxmailinglists); wait_write();
  snprintf(WriteBuf,sizeof(WriteBuf), "disk_quota %d" RET_CRLF, 
    mylimits.diskquota); wait_write();
  snprintf(WriteBuf,sizeof(WriteBuf), "max_msgcount %d" RET_CRLF, 
    mylimits.maxmsgcount); wait_write();
  snprintf(WriteBuf,sizeof(WriteBuf), "default_quota %d" RET_CRLF, 
    mylimits.defaultquota); wait_write();
  snprintf(WriteBuf,sizeof(WriteBuf), "default_maxmsgcount %d" RET_CRLF, 
    mylimits.defaultmaxmsgcount); wait_write();

  if (mylimits.disable_pop) 
    snprintf(WriteBuf,sizeof(WriteBuf), "disable_pop 1" RET_CRLF); 
  else 
    snprintf(WriteBuf,sizeof(WriteBuf), "disable_pop 0" RET_CRLF); 

  wait_write();

  if (mylimits.disable_imap) 
    snprintf(WriteBuf,sizeof(WriteBuf), "disable_imap 1" RET_CRLF);
  else
    snprintf(WriteBuf,sizeof(WriteBuf), "disable_imap 0" RET_CRLF);
  wait_write();

  if (mylimits.disable_dialup) 
    snprintf(WriteBuf,sizeof(WriteBuf), "disable_dialup 1" RET_CRLF);
  else 
    snprintf(WriteBuf,sizeof(WriteBuf), "disable_dialup 0" RET_CRLF);
  wait_write();

  if (mylimits.disable_passwordchanging) 
    snprintf(WriteBuf,sizeof(WriteBuf), "disable_password_changing 1" RET_CRLF);
  else 
    snprintf(WriteBuf,sizeof(WriteBuf), "disable_password_changing 0" RET_CRLF);
  wait_write();

  if (mylimits.disable_webmail)
    snprintf(WriteBuf,sizeof(WriteBuf), "disable_webmail 1" RET_CRLF);
  else
    snprintf(WriteBuf,sizeof(WriteBuf), "disable_webmail 0" RET_CRLF);
  wait_write();

  if (mylimits.disable_relay)
    snprintf(WriteBuf,sizeof(WriteBuf), "disable_external_relay 1" RET_CRLF);
  else
    snprintf(WriteBuf,sizeof(WriteBuf), "disable_external_relay 0" RET_CRLF);
  wait_write();

  if (mylimits.disable_smtp)
    snprintf(WriteBuf,sizeof(WriteBuf), "disable_smtp 1" RET_CRLF);
  else
    snprintf(WriteBuf,sizeof(WriteBuf), "disable_smtp 0" RET_CRLF);
  wait_write();

  if (mylimits.disable_spamassassin) 
    snprintf(WriteBuf,sizeof(WriteBuf), "disable_spamassassin 1" RET_CRLF);
  else 
    snprintf(WriteBuf,sizeof(WriteBuf), "disable_spamassassin 0" RET_CRLF);
  wait_write();

  if (mylimits.delete_spam)
    snprintf(WriteBuf,sizeof(WriteBuf), "delete_spam 1" RET_CRLF);
  else
    snprintf(WriteBuf,sizeof(WriteBuf), "delete_spam 0" RET_CRLF);
  wait_write();

  snprintf(WriteBuf,sizeof(WriteBuf), "perm_account %d" RET_CRLF, 
    mylimits.perm_account); wait_write();
  snprintf(WriteBuf,sizeof(WriteBuf), "perm_alias %d" RET_CRLF, 
    mylimits.perm_alias); wait_write();
  snprintf(WriteBuf,sizeof(WriteBuf), "perm_forward %d" RET_CRLF, 
    mylimits.perm_forward); wait_write();
  snprintf(WriteBuf,sizeof(WriteBuf), "perm_autoresponder %d" RET_CRLF, 
    mylimits.perm_autoresponder); wait_write();
  snprintf(WriteBuf,sizeof(WriteBuf), "perm_maillist %d" RET_CRLF, 
    mylimits.perm_maillist); wait_write();
  snprintf(WriteBuf,sizeof(WriteBuf), "perm_quota %d" RET_CRLF,
   (mylimits.perm_quota) | 
   (mylimits.perm_maillist_users<<VLIMIT_DISABLE_BITS) |
   (mylimits.perm_maillist_moderators<<(VLIMIT_DISABLE_BITS*2)));
  wait_write();

  snprintf(WriteBuf,sizeof(WriteBuf), "perm_defaultquota %d" RET_CRLF, 
    mylimits.perm_defaultquota); wait_write();
  wait_write();

  snprintf(WriteBuf,sizeof(WriteBuf), "." RET_CRLF);
  return(0);
}

int set_limits()
{
 char domain[156];
 struct vlimits mylimits;
 int ret;
 char *param;
 char *value;

  if ( !(AuthVpw.pw_gid & SA_ADMIN) ) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX not authorized" RET_CRLF);
    return(-1);
  }

    snprintf(WriteBuf,sizeof(WriteBuf), RET_OK);
    wait_write();
  if ((param=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf),RET_ERR "XXX domain required" RET_CRLF);
    return(-1);
  }
  snprintf(domain,sizeof(domain), param);

  if ((ret=vget_limits(domain,&mylimits))!=0){
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX could not get limits" RET_CRLF);
    return(-1);
  }

  while(fgets(ReadBuf,sizeof(ReadBuf),stdin)!=NULL ) {
    if ( ReadBuf[0]  == '.' ) break;

    if ( (param = strtok(ReadBuf,PARAM_TOKENS)) == NULL ) continue;
    if ( (value = strtok(NULL,PARAM_TOKENS)) == NULL ) continue;

    if ( strcmp(param,"max_popaccounts") == 0 ) {
      mylimits.maxpopaccounts = atoi(value);
    } else if ( strcmp(param,"max_aliases") == 0 ) {
      mylimits.maxaliases = atoi(value);
    } else if ( strcmp(param,"max_forwards") == 0 ) {
      mylimits.maxforwards = atoi(value);
    } else if ( strcmp(param,"max_autoresponders") == 0 ) {
      mylimits.maxautoresponders = atoi(value);
    } else if ( strcmp(param,"max_mailinglists") == 0 ) {
      mylimits.maxmailinglists = atoi(value);
    } else if ( strcmp(param,"disk_quota") == 0 ) {
      mylimits.diskquota = atoi(value);
    } else if ( strcmp(param,"max_msgcount") == 0 ) {
      mylimits.maxmsgcount = atoi(value);
    } else if ( strcmp(param,"default_quota") == 0 ) {
      mylimits.defaultquota = atoi(value);
    } else if ( strcmp(param,"default_maxmsgcount") == 0 ) {
      mylimits.defaultmaxmsgcount = atoi(value);
    } else if ( strcmp(param,"disable_pop") == 0 ) {
      mylimits.disable_pop = atoi(value);
    } else if ( strcmp(param,"disable_imap") == 0 ) {
      mylimits.disable_imap = atoi(value);
    } else if ( strcmp(param,"disable_dialup") == 0 ) {
      mylimits.disable_dialup = atoi(value);
    } else if ( strcmp(param,"disable_password_changing") == 0 ) {
      mylimits.disable_passwordchanging = atoi(value);
    } else if ( strcmp(param,"disable_webmail") == 0 ) {
      mylimits.disable_webmail = atoi(value);
    } else if ( strcmp(param,"disable_external_relay") == 0 ) {
      mylimits.disable_relay = atoi(value);
    } else if ( strcmp(param,"disable_smtp") == 0 ) {
      mylimits.disable_smtp = atoi(value);
    } else if ( strcmp(param,"disable_spamassassin") == 0 ) {
      mylimits.disable_spamassassin = atoi(value);
    } else if ( strcmp(param,"delete_spam") == 0 ) {
      mylimits.delete_spam = atoi(value);
    } else if ( strcmp(param,"perm_account") == 0 ) {
      mylimits.perm_account = atoi(value);
    } else if ( strcmp(param,"perm_alias") == 0 ) {
      mylimits.perm_alias = atoi(value);
    } else if ( strcmp(param,"perm_forward") == 0 ) {
      mylimits.perm_forward = atoi(value);
    } else if ( strcmp(param,"perm_autoresponder") == 0 ) {
      mylimits.perm_autoresponder = atoi(value);
    } else if ( strcmp(param,"perm_maillist") == 0 ) {
      mylimits.perm_maillist = atoi(value);
    } else if ( strcmp(param,"perm_maillist_users") == 0 ) {
      mylimits.perm_maillist_users = atoi(value);
    } else if ( strcmp(param,"perm_maillist_moderators") == 0 ) {
      mylimits.perm_maillist_moderators = atoi(value);
    } else if ( strcmp(param,"perm_quota") == 0 ) {
      mylimits.perm_quota = atoi(value);
    } else if ( strcmp(param,"perm_defaultquota") == 0 ) {
      mylimits.perm_defaultquota = atoi(value);
    }
  }

  if ( vset_limits(domain,&mylimits) < 0 ) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX could not set limits" RET_CRLF);
  } else {
    snprintf(WriteBuf,sizeof(WriteBuf),RET_OK);
  }
  return(0);
}

int del_limits()
{
 char *domain;
 int   ret;

  if ( !(AuthVpw.pw_gid & SA_ADMIN) ) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX not authorized" RET_CRLF);
    return(-1);
  }

  if ((domain=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX domain required" RET_CRLF);
    return(-1);
  }

  if ((ret=vdel_limits(domain))!=0){
    snprintf(WriteBuf,sizeof(WriteBuf),RET_ERR "XXX %s" RET_CRLF, 
      strerror(errno));
    return(-1);
  }

  snprintf(WriteBuf,sizeof(WriteBuf), RET_OK);
  return(0);
}

int get_lastauth()
{
 char *email_address;
 time_t last_auth_time;
 char *last_auth_ip;

  if ( !(AuthVpw.pw_gid & QA_ADMIN) && !(AuthVpw.pw_gid & SA_ADMIN) ) {
    snprintf(WriteBuf,sizeof(WriteBuf), RET_ERR "XXX not authorized" RET_CRLF);
    return(-1);
  }

  if ((email_address=strtok(NULL,TOKENS))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX email_address required" RET_CRLF);
    return(-1);
  }

  if ( parse_email( email_address, TmpUser, TmpDomain, AUTH_SIZE) != 0 ) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX invaild email addrress" RET_CRLF);
    return(-1);
  } 

  if (!(AuthVpw.pw_gid&SA_ADMIN) && (AuthVpw.pw_gid&QA_ADMIN) && 
       (strcmp(TheDomain,TmpDomain))!=0 ) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX not authorized for domain" RET_CRLF);
    return(-1);
  }

  if ((tmpvpw = vauth_getpw(TmpUser, TmpDomain))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf), 
      RET_ERR "XXX user does not exist" RET_CRLF);
    return(-1);
  } 

  last_auth_time = vget_lastauth(tmpvpw, TmpDomain);
  last_auth_ip = vget_lastauthip(tmpvpw, TmpDomain);

  snprintf(WriteBuf,sizeof(WriteBuf), RET_OK_MORE);
  wait_write();

  snprintf(WriteBuf, sizeof(WriteBuf), "time %ld" RET_CRLF,(long int)last_auth_time);
  wait_write();

  snprintf(WriteBuf, sizeof(WriteBuf), "ip %s" RET_CRLF, last_auth_ip);
  return(0);
}

int add_list()
{
  return(0);
}

int del_list()
{
  return(0);
}

int mod_list()
{
  return(0);
}

int quit()
{
  snprintf(WriteBuf,sizeof(WriteBuf), RET_OK);
  wait_write();
  vclose();
  exit(0);
}

int help()
{
 int i;

  snprintf(WriteBuf,sizeof(WriteBuf), RET_OK_MORE);
  wait_write();

  if (!logged_in) {
    snprintf(WriteBuf,sizeof(WriteBuf),"login user@domain password" RET_CRLF);
    wait_write();
    snprintf(WriteBuf,sizeof(WriteBuf),"clogin user@domain password" RET_CRLF);
    wait_write();
    snprintf(WriteBuf,sizeof(WriteBuf),"slogin user@domain password" RET_CRLF);
    wait_write();
  }

  for(i=0;Functions[i].command!=NULL;++i ) {
    if (logged_in >= Functions[i].level) {
      snprintf(WriteBuf, sizeof(WriteBuf), "%s %s" RET_CRLF, 
        Functions[i].command,
        Functions[i].help );
      wait_write();
    }
  }
  snprintf(WriteBuf,sizeof(WriteBuf), "." RET_CRLF);
  return(0); 
}

int bkscandir(const char *dirname,
              struct dirent ***namelist,
            int (*select)(struct dirent *),
            int (*compar)(const void *, const void *))
{
  int i;
  int entries;
  int esize;
  struct dirent* dp;
  struct dirent* dent;
  DIR * dirp;

  *namelist = NULL;
  entries = esize = 0;

  /* load the names */
  if ((dirp = opendir(dirname)) == NULL)
    return -1;

  while ((dp = readdir(dirp)) != NULL) {
    if (select == NULL || (*select)(dp)) {
      if (entries >= esize) {
        void* mem;
        esize += 10;
        if ((mem = realloc(*namelist, esize * sizeof(struct dirent*)))==NULL) {
          for (i = 0; i < entries; i++)
            free((*namelist)[i]);
          free(*namelist);
          closedir(dirp);
          return -1;
        }
        *namelist = (struct dirent**)mem;
      }
      if ((dent = (struct dirent*)malloc(sizeof(struct dirent)+MAX_FILE_NAME)) 
           == NULL) {
        for (i = 0; i < entries; i++)
          free((*namelist)[i]);
        free(*namelist);
        closedir(dirp);
        return -1;
      }
      memcpy(dent, dp, sizeof(*dp)+MAX_FILE_NAME);
      (*namelist)[entries] = dent;
      entries++;
    }
  }
  closedir(dirp);

  /* sort them */
  if (compar)
    qsort((void*)*namelist, entries, sizeof(struct dirent*), compar);
  return entries;
}

int qa_sort(const void * a, const void * b)
{
  return strcasecmp ((*(const struct dirent **) a)->d_name,
                     (*(const struct dirent **) b)->d_name);
}

