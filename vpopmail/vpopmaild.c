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
#define TOKENS " \n\t\r"
#define PARAM_TOKENS " =:\n\r"
#define PARAM_SPACE_TOKENS "=:\n\r"
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


int login();
int add_user();
int del_user();
int mod_user();
int user_info();
int add_domain();
int del_domain();
int dom_info();
int mk_dir();
int rm_dir();
int list_dir();
int rm_file();
int write_file();
int read_file();
int list_domains();
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
int get_lastauthip();
int add_list();
int del_list();
int mod_list();
int quit();
int help();

char *validate_path(char *path);

/* utility functions */
void send_user_info(struct vqpasswd *tmpvpw);

#define DEC    ( int *(*)() )


typedef struct func_t {
 char *command;
 int (*func)();
 char *help;
} func_t;

func_t Functions[] = {
{"login", login, "user@domain password<crlf>" },
{"add_user", add_user, "user@domain password<crlf>" },
{"del_user", del_user, "user@domain<crlf>" },
{"mod_user", mod_user, "user@domain (option lines)<crlf>.<crlf>" },
{"user_info", user_info, "user_domain<crlf>" },
{"add_domain", add_domain, "domain postmaster@password<crlf>" },
{"del_domain", del_domain, "domain<crlf>" },
{"dom_info", dom_info, "domain<crlf>" },
{"mk_dir", mk_dir, "/full/path/to/dir<crlf>" },
{"rm_dir", rm_dir, "/full/path/to/dir<crlf>" },
{"list_dir", list_dir, "/full/path/to/dir<crlf>" },
{"rm_file", rm_file, "/full/path/to/file<crlf>" },
{"write_file", write_file, "/full/path (data lines)<crlf>.<crlf>" },
{"read_file", read_file, "/full/path<crlf>" },
{"list_domains", list_domains, "<crlf>" },
{"list_users", list_users, "domain<crlf>" },
{"list_alias", list_alias, "domain<crlf>" },
{"list_lists", list_lists, "domain<crlf>" },
{"get_ip_map", get_ip_map, "domain<crlf>" },
{"add_ip_map", add_ip_map, "domain (not yet determined in this version)<crlf>" },
{"del_ip_map", del_ip_map, "domain<crlf>" },
{"show_ip_map", show_ip_map, "domain<crlf>" },
{"get_limits", get_limits, "domain<crlf>" },
{"set_limits", set_limits, "domain (option lines)<crlf>.<crlf>"},
{"del_limits", del_limits, "domain<crlf>" },
{"get_lastauth", get_lastauth, "user@domain<crlf>" },
{"get_lastauthip", get_lastauthip, "user@domain<crlf>" },
{"add_list", add_list, "domain listname (command line options)<crlf>" },
{"del_list", del_list, "domain listname<crlf>"},
{"mod_list", mod_list, "domain listname (command line options)<crlf>" },
{"quit", quit, "quit" },
{"help", help, "help" },
{NULL, NULL } };


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

  strncpy(WriteBuf,RET_OK,sizeof(WriteBuf));
  wait_write();

  read_size = wait_read();
  if ( read_size < 0 ) {
    strncpy(WriteBuf,RET_ERR "XXX read timeout" RET_CRLF,sizeof(WriteBuf));
    wait_write();
    exit(-1);
  } 

  /* authenticate first or drop connection */
  if ( login() < 0 ) {
    wait_write();
    vclose();
    exit(-1);
  } else {
    wait_write();
  }

  while(1) {
    read_size = wait_read();
    if ( read_size < 0 ) {
      strncpy(WriteBuf,RET_ERR "XXX read timeout" RET_CRLF,sizeof(WriteBuf));
      wait_write();
      vclose();
      exit(-1);
    } 
    if ((command=strtok(ReadBuf,TOKENS))==NULL) {
      strncpy(WriteBuf,RET_ERR "XXX Invalid command" RET_CRLF,sizeof(WriteBuf));
      wait_write();
      continue;
    }

    for(found=0,i=0;found==0&&Functions[i].command!=NULL;++i ) {
      if ( strcasecmp(Functions[i].command, command) == 0 ) { 
        found = 1;
        Functions[i].func();
      }
    }
    if ( found == 0 ) {
      strncpy(WriteBuf, RET_ERR "XXX Invalid command " RET_CRLF, sizeof(WriteBuf));
      wait_write();
    } else {
      wait_write();
    }
  }

}

int login()
{
 char *command;
 char *email;
 char *pass;
 uid_t uid;
 gid_t gid;


  if ((command=strtok(ReadBuf,TOKENS))==NULL) {
    strncpy(WriteBuf, RET_ERR "XXX authorization first" RET_CRLF, sizeof(WriteBuf));
    return(-1);
  }

  if (strcasecmp(command, Functions[0].command ) != 0 ) {
    if (strcasecmp(command, "help") == 0 ) help();
    strncpy(WriteBuf, RET_ERR "XXX authorization first" RET_CRLF, sizeof(WriteBuf));
    return(-1);
  }
  if ((email=strtok(NULL,TOKENS))==NULL) {
    strncpy(WriteBuf, RET_ERR "XXX email address required" RET_CRLF, sizeof(WriteBuf));
    return(-1);
  }

  if ((pass=strtok(NULL,TOKENS))==NULL) {
    strncpy(WriteBuf, RET_ERR "XXX password required" RET_CRLF, sizeof(WriteBuf));
    return(-2);
  }

  if ( parse_email( email, TheUser, TheDomain, AUTH_SIZE) != 0 ) {
    strncpy(WriteBuf, RET_ERR "XXX invalid login" RET_CRLF, sizeof(WriteBuf));
    return(-1); 
  }

  if ((tmpvpw = vauth_getpw(TheUser, TheDomain))==NULL) {
    strncpy(WriteBuf, RET_ERR "XXX invalid login" RET_CRLF, sizeof(WriteBuf));
    return(-1);
  }

  if ( vauth_crypt(TheUser, TheDomain, pass, tmpvpw) != 0 ) {
    strncpy(WriteBuf, RET_ERR "XXX invalid login" RET_CRLF, sizeof(WriteBuf));
    return(-1);
  } 
  strncpy(WriteBuf,RET_OK_MORE,sizeof(WriteBuf));
  wait_write();


  AuthVpw.pw_name = strdup(tmpvpw->pw_name);
  AuthVpw.pw_passwd = strdup(tmpvpw->pw_passwd);
  AuthVpw.pw_uid = tmpvpw->pw_uid;
  AuthVpw.pw_gid = tmpvpw->pw_gid;
  AuthVpw.pw_flags = tmpvpw->pw_flags;
  AuthVpw.pw_gecos = strdup(tmpvpw->pw_gecos);
  AuthVpw.pw_dir = strdup(tmpvpw->pw_dir);
  AuthVpw.pw_shell = strdup(tmpvpw->pw_shell);
  AuthVpw.pw_clear_passwd = strdup(tmpvpw->pw_clear_passwd);

  strncpy( TheUserDir, AuthVpw.pw_dir, sizeof(TheUserDir));
  strncpy( TheDomainDir, vget_assign(TheDomain,NULL,0,&uid,&gid),
    sizeof(TheDomainDir));
  snprintf(TheVpopmailDomains, sizeof(TheVpopmailDomains), "%s/domains", 
    VPOPMAILDIR);

  if ( (AuthVpw.pw_gid & QA_ADMIN) || 
              (strcmp("postmaster", AuthVpw.pw_name)==0) ) {
    AuthVpw.pw_gid |= QA_ADMIN; 
    strcpy( TheDomainDir, vget_assign(TheDomain,NULL,0,NULL,NULL));
  }

  snprintf(WriteBuf,sizeof(WriteBuf), "vpopmail_dir %s" RET_CRLF, VPOPMAILDIR);
  wait_write();

  snprintf(WriteBuf,sizeof(WriteBuf), "domain_dir %s" RET_CRLF, TheDomainDir);
  wait_write();

  snprintf(WriteBuf,sizeof(WriteBuf), "uid %d" RET_CRLF, uid);
  wait_write();

  snprintf(WriteBuf,sizeof(WriteBuf), "gid %d" RET_CRLF, gid);
  wait_write();

  send_user_info(&AuthVpw);

  strncpy(WriteBuf, "." RET_CRLF, sizeof(WriteBuf));
  return(0);
  
}

int add_user()
{
 char *email_address;
 char *password;
 char *gecos;
 int   ret;

  if ( !(AuthVpw.pw_gid & QA_ADMIN) && !(AuthVpw.pw_gid & SA_ADMIN) ) {
    strncpy(WriteBuf,RET_ERR "XXX not authorized" RET_CRLF, sizeof(WriteBuf));
    return(-1);
  }

  if ((email_address=strtok(NULL,TOKENS))==NULL) {
    strncpy(WriteBuf,RET_ERR "XXX email_address required" RET_CRLF, sizeof(WriteBuf));
    return(-1);
  }

  if ( parse_email( email_address, TmpUser, TmpDomain, AUTH_SIZE) != 0 ) {
    strncpy(WriteBuf,RET_ERR "XXX invaild email addrress" RET_CRLF, sizeof(WriteBuf));
    return(-1);
  } 

  if (!(AuthVpw.pw_gid&SA_ADMIN) && (AuthVpw.pw_gid&QA_ADMIN) && 
       (strcmp(TheDomain,TmpDomain))!=0 ) {
    strncpy(WriteBuf,RET_ERR "XXX not authorized for domain" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  }

  if ((password=strtok(NULL,TOKENS))==NULL) {
    strncpy(WriteBuf,RET_ERR "XXX password required" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  }

  if ((gecos=strtok(NULL,PARAM_SPACE_TOKENS))==NULL) {
    strncpy(WriteBuf,RET_ERR "XXX gecos required" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  }

  strncpy(WriteBuf,RET_OK,sizeof(WriteBuf));
  if ((ret=vadduser(TmpUser, TmpDomain, password, gecos, USE_POP )) < 0 ) {
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
    strncpy(WriteBuf,RET_ERR "XXX not authorized" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  }

  if ((email_address=strtok(NULL,TOKENS))==NULL) {
    strncpy(WriteBuf,RET_ERR "XXX email_address required" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  }

  if ( parse_email( email_address, TmpUser, TmpDomain, AUTH_SIZE) != 0 ) {
    strncpy(WriteBuf,RET_ERR "XXX invaild email addrress" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  } 

  if (!(AuthVpw.pw_gid&SA_ADMIN) && (AuthVpw.pw_gid&QA_ADMIN) && 
       (strcmp(TheDomain,TmpDomain))!=0 ) {
    strncpy(WriteBuf,RET_ERR "XXX not authorized for domain" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  }

  if ((ret=vdeluser(TmpUser, TmpDomain)) != VA_SUCCESS ) {
    snprintf(WriteBuf,sizeof(WriteBuf),RET_ERR "XXX %s" RET_CRLF, verror(ret));
    return(-1);
  }

  strncpy(WriteBuf,RET_OK,sizeof(WriteBuf));
  return(0);
}

int mod_user()
{
 char *email_address;
 char *param;
 char *value;
 int   ret;

  if ( !(AuthVpw.pw_gid & QA_ADMIN) && !(AuthVpw.pw_gid & SA_ADMIN) ) {
    strncpy(WriteBuf,RET_ERR "XXX not authorized" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  }

  if ((email_address=strtok(NULL,TOKENS))==NULL) {
    strncpy(WriteBuf,RET_ERR "XXX email_address required" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  }

  if ( parse_email( email_address, TmpUser, TmpDomain, AUTH_SIZE) != 0 ) {
    strncpy(WriteBuf,RET_ERR "XXX invaild email addrress" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  } 

  if (!(AuthVpw.pw_gid&SA_ADMIN) && (AuthVpw.pw_gid&QA_ADMIN) && 
       (strcmp(TheDomain,TmpDomain))!=0 ) {
    strncpy(WriteBuf,
      RET_ERR "XXX not authorized for domain" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  }

  if ((tmpvpw = vauth_getpw(TmpUser, TmpDomain))==NULL) {
    strncpy(WriteBuf, RET_ERR "XXX user does not exist" RET_CRLF,sizeof(WriteBuf));
    while(fgets(ReadBuf,sizeof(ReadBuf),stdin)!=NULL);
    return(-1);
  }

  while(fgets(ReadBuf,sizeof(ReadBuf),stdin)!=NULL ) {
    if ( ReadBuf[0]  == '.' ) break;
    if ( (param = strtok(ReadBuf,PARAM_TOKENS)) == NULL ) continue;
    if ( (value = strtok(NULL,PARAM_SPACE_TOKENS)) == NULL ) continue;

    if ( strcmp(param,"comment") == 0 ) {
      tmpvpw->pw_gecos = strdup(value);
    } else if ( strcmp(param,"quota") == 0 ) {
      if ( AuthVpw.pw_gid & SA_ADMIN || 
          (AuthVpw.pw_gid & QA_ADMIN && AuthVpw.pw_gid & V_OVERRIDE) ) {
        tmpvpw->pw_shell = strdup(value);
      }
    } else if ( strcmp(param,"encrypted_password") == 0 ) {
      tmpvpw->pw_passwd = strdup(value);

    } else if ( strcmp(param,"clear_text_password") == 0 ) {
      tmpvpw->pw_clear_passwd = strdup(value);
    } else if ( strcmp(param,"clear_all_flags") == 0 ) {
      tmpvpw->pw_gid = 0; 
    } else if ( strcmp(param,"no_password_change") == 0 ) {
      if ( AuthVpw.pw_gid & SA_ADMIN || AuthVpw.pw_gid & QA_ADMIN ) {
        if ( atoi(value) == 1 ) {
          tmpvpw->pw_gid |= NO_PASSWD_CHNG;
        } else if ( atoi(value) == 0 ) {
          tmpvpw->pw_gid &= ~NO_PASSWD_CHNG;
        }
      }
    } else if ( strcmp(param,"no_pop") == 0 ) {
      if ( AuthVpw.pw_gid & SA_ADMIN || AuthVpw.pw_gid & QA_ADMIN ) {
        if ( atoi(value) == 1 ) {
          tmpvpw->pw_gid |= NO_POP;
        } else if ( atoi(value) == 0 ) {
          tmpvpw->pw_gid &= ~NO_POP;
        }
      }
    } else if ( strcmp(param,"no_webmail") == 0 ) {
      if ( AuthVpw.pw_gid & SA_ADMIN || AuthVpw.pw_gid & QA_ADMIN ) {
        if ( atoi(value) == 1 ) {
          tmpvpw->pw_gid |= NO_WEBMAIL;
        } else if ( atoi(value) == 0 ) {
          tmpvpw->pw_gid &= ~NO_WEBMAIL;
        }
      }
    } else if ( strcmp(param,"no_imap") == 0 ) {
      if ( AuthVpw.pw_gid & SA_ADMIN || AuthVpw.pw_gid & QA_ADMIN ) {
        if ( atoi(value) == 1 ) {
          tmpvpw->pw_gid |= NO_IMAP;
        } else if ( atoi(value) == 0 ) {
          tmpvpw->pw_gid &= ~NO_IMAP;
        }
      }
    } else if ( strcmp(param,"bounce_maill") == 0 ) {
      if ( AuthVpw.pw_gid & SA_ADMIN || AuthVpw.pw_gid & QA_ADMIN ) {
        if ( atoi(value) == 1 ) {
          tmpvpw->pw_gid |= BOUNCE_MAIL;
        } else if ( atoi(value) == 0 ) {
          tmpvpw->pw_gid &= ~BOUNCE_MAIL;
        }
      }
    } else if ( strcmp(param,"no_relay") == 0 ) {
      if ( AuthVpw.pw_gid & SA_ADMIN || AuthVpw.pw_gid & QA_ADMIN ) {
        if ( atoi(value) == 1 ) {
          tmpvpw->pw_gid |= NO_RELAY;
        } else if ( atoi(value) == 0 ) {
          tmpvpw->pw_gid &= ~NO_RELAY;
        }
      }
    } else if ( strcmp(param,"no_dialup") == 0 ) {
      if ( AuthVpw.pw_gid & SA_ADMIN || AuthVpw.pw_gid & QA_ADMIN ) {
        if ( atoi(value) == 1 ) {
          tmpvpw->pw_gid |= NO_DIALUP;
        } else if ( atoi(value) == 0 ) {
          tmpvpw->pw_gid &= ~NO_DIALUP;
        }
      }
    } else if ( strcmp(param,"user_flag_0") == 0 ) {
      if ( AuthVpw.pw_gid & SA_ADMIN || AuthVpw.pw_gid & QA_ADMIN ) {
        if ( atoi(value) == 1 ) {
          tmpvpw->pw_gid |= V_USER0;
        } else if ( atoi(value) == 0 ) {
          tmpvpw->pw_gid &= ~V_USER0;
        }
      }
    } else if ( strcmp(param,"user_flag_1") == 0 ) {
      if ( AuthVpw.pw_gid & SA_ADMIN || AuthVpw.pw_gid & QA_ADMIN ) {
        if ( atoi(value) == 1 ) {
          tmpvpw->pw_gid |= V_USER1;
        } else if ( atoi(value) == 0 ) {
          tmpvpw->pw_gid &= ~V_USER1;
        }
      }
    } else if ( strcmp(param,"user_flag_2") == 0 ) {
      if ( atoi(value) == 1 ) {
        tmpvpw->pw_gid |= V_USER2;
        } else if ( atoi(value) == 0 ) {
          tmpvpw->pw_gid &= ~V_USER2;
        }
    } else if ( strcmp(param,"user_flag_3") == 0 ) {
      if ( atoi(value) == 1 ) {
        tmpvpw->pw_gid |= V_USER3;
        } else if ( atoi(value) == 0 ) {
          tmpvpw->pw_gid &= ~V_USER3;
        }
    } else if ( strcmp(param,"no_smtp") == 0 ) {
      if ( AuthVpw.pw_gid & SA_ADMIN || AuthVpw.pw_gid & QA_ADMIN ) {
        if ( atoi(value) == 1 ) {
          tmpvpw->pw_gid |= NO_SMTP;
        } else if ( atoi(value) == 0 ) {
          tmpvpw->pw_gid &= ~NO_SMTP;
        }
      }
    } else if ( strcmp(param,"system_admin_privileges") == 0 ) {
      if ( AuthVpw.pw_gid & SA_ADMIN ) {
        if ( atoi(value) == 1 ) {
          tmpvpw->pw_gid |= SA_ADMIN;
        } else if ( atoi(value) == 0 ) {
          tmpvpw->pw_gid &= ~SA_ADMIN;
        }
      }
    } else if ( strcmp(param,"domain_admin_privileges") == 0 ) {
      if ( AuthVpw.pw_gid & SA_ADMIN || AuthVpw.pw_gid & QA_ADMIN ) {
        if ( atoi(value) == 1 ) {
          tmpvpw->pw_gid |= QA_ADMIN;
        } else if ( atoi(value) == 0 ) {
          tmpvpw->pw_gid &= ~QA_ADMIN;
        }
      }
    } else if ( strcmp(param,"override_domain_limits") == 0 ) {
      if ( AuthVpw.pw_gid & SA_ADMIN ) {
        if ( atoi(value) == 1 ) {
          tmpvpw->pw_gid |= V_OVERRIDE;
        } else if ( atoi(value) == 0 ) {
          tmpvpw->pw_gid &= ~V_OVERRIDE;
        }
      }
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
    } else {
      fprintf(stdout, "invalid option: %s" RET_CRLF, param);fflush(stdout);
    }
  }

  if ( (ret=vauth_setpw( tmpvpw, TmpDomain )) != 0 ) {
    snprintf(WriteBuf,sizeof(WriteBuf),RET_ERR "XXX %s" RET_CRLF, verror(ret)); 
  } else {
    strncpy(WriteBuf,RET_OK,sizeof(WriteBuf));
  }

  return(0);
}

int user_info()
{
 char *email_address;

  if ( !(AuthVpw.pw_gid & QA_ADMIN) && !(AuthVpw.pw_gid & SA_ADMIN) ) {
    strncpy(WriteBuf,RET_ERR "XXX not authorized" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  }

  if ((email_address=strtok(NULL,TOKENS))==NULL) {
    strncpy(WriteBuf,RET_ERR "XXX email_address required" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  }

  if ( parse_email( email_address, TmpUser, TmpDomain, AUTH_SIZE) != 0 ) {
    strncpy(WriteBuf,RET_ERR "XXX invaild email addrress" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  } 

  if (!(AuthVpw.pw_gid&SA_ADMIN) && (AuthVpw.pw_gid&QA_ADMIN) && 
       (strcmp(TheDomain,TmpDomain))!=0 ) {
    strncpy(WriteBuf, RET_ERR "XXX not authorized for domain" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  }

  if ((tmpvpw = vauth_getpw(TmpUser, TmpDomain))==NULL) {
    strncpy(WriteBuf,RET_ERR "XXX user does not exist" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  } 

  strncpy(WriteBuf,RET_OK_MORE,sizeof(WriteBuf));
  wait_write();

  send_user_info(tmpvpw);
  strncpy(WriteBuf, "." RET_CRLF, sizeof(WriteBuf));
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

  if ( tmpvpw->pw_gid & NO_PASSWD_CHNG ) {
    strncpy(WriteBuf, "no_password_change 1" RET_CRLF, sizeof(WriteBuf));
  } else {
    strncpy(WriteBuf, "no_password_change 0" RET_CRLF, sizeof(WriteBuf));
  }
  wait_write();

  if ( tmpvpw->pw_gid & NO_POP ) {
    strncpy(WriteBuf, "no_pop 1" RET_CRLF, sizeof(WriteBuf));
  } else {
    strncpy(WriteBuf, "no_pop 0" RET_CRLF, sizeof(WriteBuf));
  }
  wait_write();

  if ( tmpvpw->pw_gid & NO_WEBMAIL ) {
    strncpy(WriteBuf, "no_webmail 1" RET_CRLF, sizeof(WriteBuf));
  } else {
    strncpy(WriteBuf, "no_webmail 0" RET_CRLF, sizeof(WriteBuf));
  }
  wait_write();

  if ( tmpvpw->pw_gid & NO_IMAP ) {
    strncpy(WriteBuf, "no_imap 1" RET_CRLF, sizeof(WriteBuf));
  } else {
    strncpy(WriteBuf, "no_imap 0" RET_CRLF, sizeof(WriteBuf));
  }
  wait_write();

  if ( tmpvpw->pw_gid & BOUNCE_MAIL ) {
    strncpy(WriteBuf, "bounce_mail 1" RET_CRLF, sizeof(WriteBuf));
  } else {
    strncpy(WriteBuf, "bounce_mail 0" RET_CRLF, sizeof(WriteBuf));
  }
  wait_write();
  if ( tmpvpw->pw_gid & NO_RELAY ) {
    strncpy(WriteBuf, "no_relay 1" RET_CRLF, sizeof(WriteBuf));
  } else {
    strncpy(WriteBuf, "no_relay 0" RET_CRLF, sizeof(WriteBuf));
  }
  wait_write();
  if ( tmpvpw->pw_gid & NO_DIALUP ) {
    strncpy(WriteBuf, "no_dialup 1" RET_CRLF, sizeof(WriteBuf));
  } else {
    strncpy(WriteBuf, "no_dialup 0" RET_CRLF, sizeof(WriteBuf));
  }
  wait_write();
  if ( tmpvpw->pw_gid & V_USER0 ) {
    strncpy(WriteBuf, "user_flag_0 1" RET_CRLF, sizeof(WriteBuf));
  } else {
    strncpy(WriteBuf, "user_flag_0 0" RET_CRLF, sizeof(WriteBuf));
  }
  wait_write();
  if ( tmpvpw->pw_gid & V_USER1 ) {
    strncpy(WriteBuf, "user_flag_1 1" RET_CRLF, sizeof(WriteBuf));
  } else {
    strncpy(WriteBuf, "user_flag_1 0" RET_CRLF, sizeof(WriteBuf));
  }
  wait_write();
  if ( tmpvpw->pw_gid & V_USER2 ) {
    strncpy(WriteBuf, "user_flag_2 1" RET_CRLF, sizeof(WriteBuf));
  } else {
    strncpy(WriteBuf, "user_flag_2 0" RET_CRLF, sizeof(WriteBuf));
  }
  wait_write();
  if ( tmpvpw->pw_gid & V_USER3 ) {
    strncpy(WriteBuf, "user_flag_3 1" RET_CRLF, sizeof(WriteBuf));
  } else {
    strncpy(WriteBuf, "user_flag_3 0" RET_CRLF, sizeof(WriteBuf));
  }
  wait_write();
  if ( tmpvpw->pw_gid & NO_SMTP ) {
    strncpy(WriteBuf, "no_smtp 1" RET_CRLF, sizeof(WriteBuf));
  } else {
    strncpy(WriteBuf, "no_smtp 0" RET_CRLF, sizeof(WriteBuf));
  }
  wait_write();
  if ( tmpvpw->pw_gid & QA_ADMIN ) {
    strncpy(WriteBuf, "domain_admin_privileges 1" RET_CRLF, sizeof(WriteBuf));
  } else {
    strncpy(WriteBuf, "domain_admin_privileges 0" RET_CRLF, sizeof(WriteBuf));
  }
  wait_write();
  if ( tmpvpw->pw_gid & V_OVERRIDE ) {
    strncpy(WriteBuf, "override_domain_limits 1" RET_CRLF, sizeof(WriteBuf));
  } else {
    strncpy(WriteBuf, "override_domain_limits 0" RET_CRLF, sizeof(WriteBuf));
  }
  wait_write();
  if ( tmpvpw->pw_gid & NO_SPAMASSASSIN ) {
    strncpy(WriteBuf, "no_spamassassin 1" RET_CRLF, sizeof(WriteBuf));
  } else {
    strncpy(WriteBuf, "no_spamassassin 0" RET_CRLF, sizeof(WriteBuf));
  }
  wait_write();
  if ( tmpvpw->pw_gid & DELETE_SPAM ) {
    strncpy(WriteBuf, "delete_spam 1" RET_CRLF, sizeof(WriteBuf));
  } else {
    strncpy(WriteBuf, "delete_spam 0" RET_CRLF, sizeof(WriteBuf));
  }
  wait_write();
  if ( tmpvpw->pw_gid & SA_ADMIN ) {
    strncpy(WriteBuf, "system_admin_privileges 1" RET_CRLF, sizeof(WriteBuf));
  } else {
    strncpy(WriteBuf, "system_admin_privileges 0" RET_CRLF, sizeof(WriteBuf));
  }
  wait_write();
  strncpy(WriteBuf, "." RET_CRLF, sizeof(WriteBuf));

}

int add_domain()
{
 char *domain;
 char *password;
 int   ret;

  if ( !(AuthVpw.pw_gid & SA_ADMIN) ) {
    strncpy(WriteBuf,RET_ERR "XXX not authorized" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  }

  if ((domain=strtok(NULL,TOKENS))==NULL) {
    strncpy(WriteBuf,RET_ERR "XXX domain required" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  }

  if ((password=strtok(NULL,TOKENS))==NULL) {
    strncpy(WriteBuf,RET_ERR "XXX password required" RET_CRLF,sizeof(WriteBuf));
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

  strncpy(WriteBuf,RET_OK,sizeof(WriteBuf));
  return(0);
}

int del_domain()
{
 char *domain;
 int   ret;

  if ( !(AuthVpw.pw_gid & SA_ADMIN) ) {
    strncpy(WriteBuf,RET_ERR "XXX not authorized" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  }

  if ((domain=strtok(NULL,TOKENS))==NULL) {
    strncpy(WriteBuf,RET_ERR "XXX domain required" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  }

  if ((ret=vdeldomain(domain))!=VA_SUCCESS){
    snprintf(WriteBuf,sizeof(WriteBuf),RET_ERR "XXX %s" RET_CRLF, verror(ret));
    return(-1);
  }

  strncpy(WriteBuf,RET_OK,sizeof(WriteBuf));
  return(0);
}

int dom_info()
{
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
    strncpy(WriteBuf,INVALID_DIRECTORY,sizeof(WriteBuf));
    return(NULL);
  }

  /* check for fake out path */
  if ( strstr(path,"%") != NULL ) {
    strncpy(WriteBuf,INVALID_DIRECTORY,sizeof(WriteBuf));
    return(NULL);
  }

  /* expand the path */
  if ( path[0] == '/' ) {
    strncpy(newpath,path,sizeof(newpath));
  } else { 
    slash = strchr( path, '/');
    if ( slash == NULL ) {
      strncpy(WriteBuf,INVALID_DIRECTORY,sizeof(WriteBuf));
      return(NULL);
    }
    atsign = strchr(path,'@');

    /* possible email address */
    if ( atsign != NULL ) {
      if ( atsign > slash ) {
        strncpy(WriteBuf,INVALID_DIRECTORY,sizeof(WriteBuf));
        return(NULL);
      }
      for(i=0;path[i]!='/'&&path[i]!=0&&i<256;++i) {
        theemail[i] = path[i];
      }
      theemail[i] = 0;

      if ( parse_email( theemail, theuser, thedomain, 256) != 0 ) {
        strncpy(WriteBuf,INVALID_DIRECTORY,sizeof(WriteBuf));
        return(NULL);
      } 

      if ((myvpw = vauth_getpw(theuser, thedomain))==NULL) {
        strncpy(WriteBuf,INVALID_DIRECTORY,sizeof(WriteBuf));
        return(NULL);
      }


      /* limit domain admins to their domains */
      if ( AuthVpw.pw_gid & QA_ADMIN ) {
        if ( strncmp(TheDomain,thedomain,strlen(TheDomain))!=0 ) {
          strncpy(WriteBuf,INVALID_DIRECTORY,sizeof(WriteBuf));
          return(NULL);
        }

      /* limit users to their accounts */
      } else if ( !(AuthVpw.pw_gid&SA_ADMIN) ){
        if ( strcmp(TheUser, theuser) != 0 || 
             strcmp(TheDomain, thedomain) != 0 ) {
          strncpy(WriteBuf,INVALID_DIRECTORY,sizeof(WriteBuf));
          return(NULL);
        }
      }
      strncpy(newpath, myvpw->pw_dir, sizeof(newpath));
      strncat(newpath,&path[i],sizeof(newpath));
    } else {
      for(i=0;path[i]!='/'&&path[i]!=0&&i<256;++i) {
        thedomain[i] = path[i];
      }
      thedomain[i] = 0;
      if ( vget_assign(thedomain, thedir,sizeof(thedir),NULL,NULL) == NULL ) {
        strncpy(WriteBuf,INVALID_DIRECTORY,sizeof(WriteBuf));
        return(NULL);
      } 
      strncpy(newpath,thedir,sizeof(newpath));
      strncat(newpath,&path[i],sizeof(newpath));
    }
  }

  if ( AuthVpw.pw_gid & SA_ADMIN ) { 
    if ( strncmp(TheVpopmailDomains,newpath,strlen(TheVpopmailDomains))!=0 ) {
      strncpy(WriteBuf,RET_ERR "XXX unauthorized directory" RET_CRLF,
        sizeof(WriteBuf));
      return(NULL);
    }
  } else if ( AuthVpw.pw_gid & QA_ADMIN ) {
    if ( strncmp(TheDomainDir,newpath,strlen(TheDomainDir)) !=0 ) {
      strncpy(WriteBuf,RET_ERR "XXX unauthorized directory" RET_CRLF,
        sizeof(WriteBuf));
      return(NULL);
    }
  } else {
    if ( strncmp(TheUserDir,newpath,strlen(TheUserDir))!=0 ) {
      strncpy(WriteBuf,RET_ERR "XXX unauthorized directory" RET_CRLF,
        sizeof(WriteBuf));
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
    strncpy(WriteBuf,RET_ERR "XXX directory required" RET_CRLF,
      sizeof(WriteBuf));
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

  strncpy(WriteBuf,RET_OK,sizeof(WriteBuf));
  return(0);
}

int rm_dir()
{
 char *dir;

  /* must supply directory parameter */
  if ((dir=strtok(NULL,TOKENS))==NULL) {
    strncpy(WriteBuf,RET_ERR "XXX directory required" RET_CRLF,
      sizeof(WriteBuf));
    return(-1);
  }

  if ( (dir=validate_path(dir)) == NULL ) return(-1);

  /* recursive directory delete */ 
  if ( vdelfiles(dir) < 0 ) {
    snprintf(WriteBuf,sizeof(WriteBuf),RET_ERR "XXX %s" RET_CRLF, strerror(errno));
    return(-1);
  }
  strncpy(WriteBuf,RET_OK,sizeof(WriteBuf));
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
    strncpy(WriteBuf,RET_ERR "XXX directory required" RET_CRLF,
      sizeof(WriteBuf));
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

  strncpy(WriteBuf,RET_OK_MORE,sizeof(WriteBuf));
  wait_write();

  while((mydirent=readdir(mydir))!=NULL){

    /* skip the current directory and the parent directory entries */
    if ( strncmp(mydirent->d_name,".", 2) ==0 || 
         strncmp(mydirent->d_name,"..", 3)==0 ) continue;
   
    if ( lstat(mydirent->d_name,&statbuf) < 0 ) {
      printf("error on stat of %s\n", mydirent->d_name);
      exit(-1);
    }
    strncpy( WriteBuf, mydirent->d_name,sizeof(WriteBuf));
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

  strncpy(WriteBuf,"." RET_CRLF,sizeof(WriteBuf));
  return(0);
}

int rm_file()
{
 char *filename;


  /* must supply directory parameter */
  if ((filename=strtok(NULL,TOKENS))==NULL) {
    strncpy(WriteBuf,RET_ERR "XXX filename required" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  }

  if ( (filename=validate_path(filename)) == NULL ) return(-1);

  /* unlink filename */ 
  if ( unlink(filename) < 0 ) {
    snprintf(WriteBuf,sizeof(WriteBuf),RET_ERR "XXX %s" RET_CRLF, 
      strerror(errno));
    return(-1);
  }

  strncpy(WriteBuf,RET_OK,sizeof(WriteBuf));
  return(0);
}

int write_file()
{
  strncpy(WriteBuf,RET_OK,sizeof(WriteBuf));
  return(0);
}

int read_file()
{
 char *filename;
 char tmpbuf[1024];
 FILE *fs;

  /* must supply directory parameter */
  if ((filename=strtok(NULL,TOKENS))==NULL) {
    strncpy(WriteBuf,RET_ERR "XXX filename required" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  }

  if ( (filename=validate_path(filename)) == NULL ) return(-1);

  if ( (fs=fopen(filename,"r"))==NULL) {
    snprintf(WriteBuf,sizeof(WriteBuf),RET_ERR "XXX %s" RET_CRLF, 
      strerror(errno));
    return(-1);
  }

  strncpy(WriteBuf,RET_OK_MORE,sizeof(WriteBuf));
  wait_write();

  while(fgets(tmpbuf,sizeof(tmpbuf),fs)!=NULL){
    if ( strcmp(tmpbuf, "." RET_CRLF) == 0 || 
         strcmp(tmpbuf,".\r" RET_CRLF) == 0 ) {
      strncpy(WriteBuf, ".", sizeof(WriteBuf));
      strncat(WriteBuf, tmpbuf, sizeof(WriteBuf));
    } else {
      memcpy(WriteBuf,tmpbuf,sizeof(tmpbuf));
    }
    wait_write();
  }
  fclose(fs);

  strncpy(WriteBuf,"." RET_CRLF,sizeof(WriteBuf));
  return(0);
}

int list_domains()
{
 FILE *fs;
 char tmpbuf[1024];
 char *domain;
 char *alias_domain;
 char *tmpstr;
 int page = 0;
 int lines_per_page = 0;
 int count;
 int start;
 int end;

  if ( !(AuthVpw.pw_gid & SA_ADMIN) ) {
    strncpy(WriteBuf,RET_ERR "XXX not authorized" RET_CRLF,sizeof(WriteBuf));
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


  snprintf(tmpbuf,sizeof(tmpbuf), "%s/users/assign", QMAILDIR);
  
  if ( (fs=fopen(tmpbuf,"r")) == NULL ) {
    strncpy(WriteBuf, RET_ERR "XXX could not open assign file" RET_CRLF,
      sizeof(WriteBuf));
    return(-1);
  }

  strncpy(WriteBuf,RET_OK_MORE,sizeof(WriteBuf));
  wait_write();

  count = 0;
  while(fgets(tmpbuf,sizeof(tmpbuf),fs) != NULL ) {
    if ( (domain = strtok(tmpbuf,LIST_DOMAIN_TOKENS))==NULL ) continue;
    if ( (alias_domain = strtok(NULL,LIST_DOMAIN_TOKENS))==NULL ) continue;

    /* skip the first + character */
    ++domain;

    /* skip the last - character */
    domain[strlen(domain)-1] = 0;

    if ( end>0 ) {
      if ( count>=start && count<end ) {
        snprintf(WriteBuf,sizeof(WriteBuf), "%s %s" RET_CRLF, 
          domain, alias_domain);
        wait_write();
      } else if ( count>=end ) {
        break;
      }
    } else { 
      snprintf(WriteBuf,sizeof(WriteBuf), "%s %s" RET_CRLF, 
        domain, alias_domain);
      wait_write();
    }
    ++count;
  }
  fclose(fs);
  strncpy(WriteBuf,"." RET_CRLF,sizeof(WriteBuf));
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
    strncpy(WriteBuf,RET_ERR "XXX not authorized" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  }

  if ((domain=strtok(NULL,TOKENS))==NULL) {
    strncpy(WriteBuf,RET_ERR "XXX email_address required" RET_CRLF,sizeof(WriteBuf));
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
    strncpy(WriteBuf,RET_ERR "XXX not authorized for domain" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  }

  strncpy(WriteBuf, RET_OK_MORE, sizeof(WriteBuf));
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
  strncpy(WriteBuf,"." RET_CRLF,sizeof(WriteBuf));
  return(0);
}

int list_alias()
{
  return(0);
}

int list_lists()
{
  return(0);
}

int get_ip_map()
{
  return(0);
}

int add_ip_map()
{
  return(0);
}

int del_ip_map()
{
 return(0);
}

int show_ip_map()
{
  return(0);
}

int get_limits()
{
 char *domain;
 int   ret;
 struct vlimits mylimits;

  if ( !(AuthVpw.pw_gid & SA_ADMIN) ) {
    strncpy(WriteBuf,RET_ERR "XXX not authorized" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  }

  if ((domain=strtok(NULL,TOKENS))==NULL) {
    strncpy(WriteBuf,RET_ERR "XXX domain required" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  }

  if ((ret=vget_limits(domain,&mylimits))!=0){
    strncpy(WriteBuf,RET_ERR "XXX could not get limits" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  }

  strncpy(WriteBuf,RET_OK_MORE,sizeof(WriteBuf));
  wait_write();

  snprintf(WriteBuf,sizeof(WriteBuf), "maxpopaccounts: %d" RET_CRLF, 
    mylimits.maxpopaccounts); wait_write();
  snprintf(WriteBuf,sizeof(WriteBuf), "maxaliases: %d" RET_CRLF, 
    mylimits.maxaliases); wait_write();
  snprintf(WriteBuf,sizeof(WriteBuf), "maxforwards: %d" RET_CRLF, 
    mylimits.maxforwards); wait_write();
  snprintf(WriteBuf,sizeof(WriteBuf), "maxautoresponders: %d" RET_CRLF, 
    mylimits.maxautoresponders); wait_write();
  snprintf(WriteBuf,sizeof(WriteBuf), "maxmailinglists: %d" RET_CRLF, 
    mylimits.maxmailinglists); wait_write();
  snprintf(WriteBuf,sizeof(WriteBuf), "quota: %d" RET_CRLF, 
    mylimits.diskquota); wait_write();
  snprintf(WriteBuf,sizeof(WriteBuf), "maxmsgcount: %d" RET_CRLF, 
    mylimits.maxmsgcount); wait_write();
  snprintf(WriteBuf,sizeof(WriteBuf), "default_quota: %d" RET_CRLF, 
    mylimits.defaultquota); wait_write();
  snprintf(WriteBuf,sizeof(WriteBuf), "default_maxmsgcount: %d" RET_CRLF, 
    mylimits.defaultmaxmsgcount); wait_write();
  if (mylimits.disable_pop) {
    snprintf(WriteBuf,sizeof(WriteBuf), "disable_pop" RET_CRLF); 
    wait_write();
  }
  if (mylimits.disable_imap) {
    snprintf(WriteBuf,sizeof(WriteBuf), "disable_imap" RET_CRLF);
    wait_write();
  }
  if (mylimits.disable_dialup) {
    snprintf(WriteBuf,sizeof(WriteBuf), "disable_dialup" RET_CRLF);
    wait_write();
  }
  if (mylimits.disable_passwordchanging) {
    snprintf(WriteBuf,sizeof(WriteBuf), "disable_password_changing" RET_CRLF);
    wait_write();
  }
  if (mylimits.disable_webmail) {
    snprintf(WriteBuf,sizeof(WriteBuf), "disable_webmail" RET_CRLF);
    wait_write();
  }
  if (mylimits.disable_relay) {
    snprintf(WriteBuf,sizeof(WriteBuf), "disable_external_relay" RET_CRLF);
    wait_write();
  }
  if (mylimits.disable_smtp) {
    snprintf(WriteBuf,sizeof(WriteBuf), "disable_smtp" RET_CRLF);
    wait_write();
  }
  if (mylimits.disable_spamassassin) {
    snprintf(WriteBuf,sizeof(WriteBuf), "disable_spamassassin%s", RET_CRLF);
    wait_write();
  }
  if (mylimits.delete_spam) {
    snprintf(WriteBuf,sizeof(WriteBuf), "delete_spam%s", RET_CRLF);
    wait_write();
  }
  snprintf(WriteBuf,sizeof(WriteBuf), "perm_account: %d" RET_CRLF, 
    mylimits.perm_account); wait_write();
  snprintf(WriteBuf,sizeof(WriteBuf), "perm_alias: %d" RET_CRLF, 
    mylimits.perm_alias); wait_write();
  snprintf(WriteBuf,sizeof(WriteBuf), "perm_forward: %d" RET_CRLF, 
    mylimits.perm_forward); wait_write();
  snprintf(WriteBuf,sizeof(WriteBuf), "perm_autoresponder: %d" RET_CRLF, 
    mylimits.perm_autoresponder); wait_write();
  snprintf(WriteBuf,sizeof(WriteBuf), "perm_maillist: %d" RET_CRLF, 
    mylimits.perm_maillist); wait_write();
  snprintf(WriteBuf,sizeof(WriteBuf), "perm_quota: %d" RET_CRLF,
   (mylimits.perm_quota) | 
   (mylimits.perm_maillist_users<<VLIMIT_DISABLE_BITS) |
   (mylimits.perm_maillist_moderators<<(VLIMIT_DISABLE_BITS*2)));
  wait_write();

  snprintf(WriteBuf,sizeof(WriteBuf), "perm_defaultquota: %d" RET_CRLF, 
    mylimits.perm_defaultquota); wait_write();
  wait_write();

  strncpy(WriteBuf,"." RET_CRLF,sizeof(WriteBuf));
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
    strncpy(WriteBuf,RET_ERR "XXX not authorized" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  }

  if ((param=strtok(NULL,TOKENS))==NULL) {
    strncpy(WriteBuf,RET_ERR "XXX domain required" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  }
  strncpy(domain,param,sizeof(domain));

  if ((ret=vget_limits(domain,&mylimits))!=0){
    strncpy(WriteBuf,RET_ERR "XXX could not get limits" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  }

  while(fgets(ReadBuf,sizeof(ReadBuf),stdin)!=NULL ) {
    if ( ReadBuf[0]  == '.' ) break;

    if ( (param = strtok(ReadBuf,PARAM_TOKENS)) == NULL ) continue;
    if ( (value = strtok(NULL,PARAM_TOKENS)) == NULL ) continue;

    if ( strcmp(param,"maxpopaccounts") == 0 ) {
      mylimits.maxpopaccounts = atoi(value);
    } else if ( strcmp(param,"maxaliases") == 0 ) {
      mylimits.maxaliases = atoi(value);
    } else if ( strcmp(param,"maxforwards") == 0 ) {
      mylimits.maxforwards = atoi(value);
    } else if ( strcmp(param,"maxautoresponders") == 0 ) {
      mylimits.maxautoresponders = atoi(value);
    } else if ( strcmp(param,"maxmailinglists") == 0 ) {
      mylimits.maxmailinglists = atoi(value);
    } else if ( strcmp(param,"diskquota") == 0 ) {
      mylimits.diskquota = atoi(value);
    } else if ( strcmp(param,"maxmsgcount") == 0 ) {
      mylimits.maxmsgcount = atoi(value);
    } else if ( strcmp(param,"defaultquota") == 0 ) {
      mylimits.defaultquota = atoi(value);
    } else if ( strcmp(param,"defaultmaxmsgcount") == 0 ) {
      mylimits.defaultmaxmsgcount = atoi(value);
    } else if ( strcmp(param,"disable_pop") == 0 ) {
      mylimits.disable_pop = atoi(value);
    } else if ( strcmp(param,"disable_imap") == 0 ) {
      mylimits.disable_imap = atoi(value);
    } else if ( strcmp(param,"disable_dialup") == 0 ) {
      mylimits.disable_dialup = atoi(value);
    } else if ( strcmp(param,"disable_passwordchanging") == 0 ) {
      mylimits.disable_passwordchanging = atoi(value);
    } else if ( strcmp(param,"disable_webmail") == 0 ) {
      mylimits.disable_webmail = atoi(value);
    } else if ( strcmp(param,"disable_relay") == 0 ) {
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
    strncpy(WriteBuf,RET_ERR "XXX could not set limits" RET_CRLF,sizeof(WriteBuf));
  } else {
    strncpy(WriteBuf,RET_OK,sizeof(WriteBuf));
  }
  return(0);
}

int del_limits()
{
 char *domain;
 int   ret;

  if ( !(AuthVpw.pw_gid & SA_ADMIN) ) {
    strncpy(WriteBuf,RET_ERR "XXX not authorized" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  }

  if ((domain=strtok(NULL,TOKENS))==NULL) {
    strncpy(WriteBuf,RET_ERR "XXX domain required" RET_CRLF,sizeof(WriteBuf));
    return(-1);
  }

  if ((ret=vdel_limits(domain))!=0){
    snprintf(WriteBuf,sizeof(WriteBuf),RET_ERR "XXX %s" RET_CRLF, strerror(errno));
    return(-1);
  }

  strncpy(WriteBuf,RET_OK,sizeof(WriteBuf));
  return(0);
}

int get_lastauth()
{
 char *email_address;
 time_t last_auth_time;

  if ( !(AuthVpw.pw_gid & QA_ADMIN) && !(AuthVpw.pw_gid & SA_ADMIN) ) {
    strncpy(WriteBuf,RET_ERR "XXX not authorized" RET_CRLF, sizeof(WriteBuf));
    return(-1);
  }

  if ((email_address=strtok(NULL,TOKENS))==NULL) {
    strncpy(WriteBuf,RET_ERR "XXX email_address required" RET_CRLF, sizeof(WriteBuf));
    return(-1);
  }

  if ( parse_email( email_address, TmpUser, TmpDomain, AUTH_SIZE) != 0 ) {
    strncpy(WriteBuf,RET_ERR "XXX invaild email addrress" RET_CRLF, sizeof(WriteBuf));
    return(-1);
  } 

  if (!(AuthVpw.pw_gid&SA_ADMIN) && (AuthVpw.pw_gid&QA_ADMIN) && 
       (strcmp(TheDomain,TmpDomain))!=0 ) {
    strncpy(WriteBuf,RET_ERR "XXX not authorized for domain" RET_CRLF, sizeof(WriteBuf));
    return(-1);
  }

  if ((tmpvpw = vauth_getpw(TmpUser, TmpDomain))==NULL) {
    strncpy(WriteBuf,RET_ERR "XXX user does not exist" RET_CRLF, sizeof(WriteBuf));
    return(-1);
  } 

  last_auth_time = vget_lastauth(tmpvpw, TmpDomain);

  strncpy(WriteBuf,RET_OK_MORE,sizeof(WriteBuf));
  wait_write();

  snprintf(WriteBuf, sizeof(WriteBuf), "%ld" RET_CRLF,(long int)last_auth_time);
  return(0);
}

int get_lastauthip()
{
 char *email_address;
 char *last_auth_ip;

  if ( !(AuthVpw.pw_gid & QA_ADMIN) && !(AuthVpw.pw_gid & SA_ADMIN) ) {
    strncpy(WriteBuf,RET_ERR "XXX not authorized" RET_CRLF, sizeof(WriteBuf));
    return(-1);
  }

  if ((email_address=strtok(NULL,TOKENS))==NULL) {
    strncpy(WriteBuf,RET_ERR "XXX email_address required" RET_CRLF, sizeof(WriteBuf));
    return(-1);
  }

  if ( parse_email( email_address, TmpUser, TmpDomain, AUTH_SIZE) != 0 ) {
    strncpy(WriteBuf,RET_ERR "XXX invaild email addrress%s" RET_CRLF, sizeof(WriteBuf));
    return(-1);
  } 

  if ( !(AuthVpw.pw_gid&SA_ADMIN) && (AuthVpw.pw_gid&QA_ADMIN) && 
        (strcmp(TheDomain,TmpDomain))!=0 ) {
    strncpy(WriteBuf,RET_ERR "XXX not authorized for domain" RET_CRLF, sizeof(WriteBuf));
    return(-1);
  }

  if ((tmpvpw = vauth_getpw(TmpUser, TmpDomain))==NULL) {
    strncpy(WriteBuf,RET_ERR "XXX user does not exist" RET_CRLF, sizeof(WriteBuf));
    return(-1);
  } 

  strncpy(WriteBuf,RET_OK_MORE,sizeof(WriteBuf));
  wait_write();

  last_auth_ip = vget_lastauthip(tmpvpw, TmpDomain);

  snprintf(WriteBuf, sizeof(WriteBuf), "%s" RET_CRLF, last_auth_ip);
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
  strncpy(WriteBuf,RET_OK,sizeof(WriteBuf));
  wait_write();
  vclose();
  exit(0);
}

int help()
{
 int i;

  strncpy(WriteBuf,RET_OK_MORE,sizeof(WriteBuf));
  wait_write();

  for(i=0;Functions[i].command!=NULL;++i ) {
    snprintf(WriteBuf, sizeof(WriteBuf), "%s %s" RET_CRLF, 
      Functions[i].command,
      Functions[i].help );
    wait_write();
  }
  strncpy(WriteBuf,"." RET_CRLF,sizeof(WriteBuf));
  return(0); 
}
