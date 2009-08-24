/*
 * vldap.c
 * part of the vpopmail package
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
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <utime.h>
#include <lber.h>
#include <ldap.h>
#include "config.h"
#include "vpopmail.h"
#include "vauth.h"
#include "vldap.h"

LDAP *ld = NULL;
LDAPMessage *glm = NULL;

char *ldap_fields[8] = {
  "uid",			/* 0 pw_name   */ 
  "userPassword",		/* 1 pw_passwd */
  "qmailUID",			/* 2 pw_uid    */
  "qmailGID",			/* 3 pw_gid    */
  "qmaildomain",		/* 4 pw_gecos  */
  "mailMessageStore",		/* 5 pw_dir    */
  "mailQuota",			/* 6 pw_shell  */
  "objectclass"			/* 7 ldap      */
};

struct vqpasswd *vauth_getpw(char *user, char *domain)
{
  int ret = 0;
  static struct vqpasswd vpw;
  LDAPMessage *res = NULL, *msg = NULL;
  char *filter = NULL, **vals = NULL, *h = NULL, *t = NULL, *passwd = NULL;
  int eret = 0;
  char *basedn = NULL;

  verrori = 0;
  lowerit(user);
  lowerit(domain);

  ret = (strlen(user) + 32 + 1);
  eret = (strlen(VLDAP_BASEDN) - 2 + strlen(domain) + 1);

  filter = (char *)malloc(ret);
  if (filter == NULL) {
     return NULL;
  }
  
  memset((char *)filter, 0, ret);
  basedn = (char *)malloc(eret);
  if (basedn == NULL) {
     free(filter);
     return NULL;
  }

  memset((char *)basedn, 0, eret);

  snprintf(filter, ret, "(&(objectclass=qmailUser)(uid=%s))", user);
  snprintf(basedn, eret, VLDAP_BASEDN, domain);

  if (ld == NULL) {
     ld = ldap_init(VLDAP_SERVER, VLDAP_PORT);
     if (ld == NULL) {
        free(filter);
        return NULL;
     }
 
     ret = ldap_simple_bind_s(ld, VLDAP_USER, VLDAP_PASSWORD);
     if (ret != LDAP_SUCCESS) {
        free(filter);
        return NULL;
     }
  }

  ret = ldap_search_s(ld, basedn, LDAP_SCOPE_SUBTREE,
                      filter, vldap_attrs, 0, &res);
  free(basedn);
  free(filter);
  
  if (ret != LDAP_SUCCESS) return NULL;
     
  msg = ldap_first_entry(ld, res);
  ret = ldap_count_entries(ld, msg);

  if (ret != 1) return NULL;
  
  memset((struct vqpasswd *)&vpw, 0, sizeof(struct vqpasswd));
  
  /*
     Fetch userPassword first so we can make sure
     we're able to handle it's password encryption (if any)
  */
 
  vals = ldap_get_values(ld, msg, "userPassword");
  if (vals == NULL)
     return NULL;

  t = h = NULL;

  passwd = (char *)malloc((strlen(*vals) + 1));
  if (passwd == NULL)
     return NULL;

  memset((char *)passwd, 0, (strlen(*vals) + 1));
  memcpy((char *)passwd, (char *)(*vals), strlen(*vals));  

  if (*passwd == '{') {
     for (t = h = (passwd + 1); *t; t++) {
         if (*t == '}') {
            *t++ = '\0';

            /*
               This is really shitty to do, but we keep the pointer
               as (h - 1).

               vol@inter7.com
            */
            passwd = t;

            /*
               Check against the encryption method, and if we see something
               we dont recognize or support, invalidate user login.

               vol@inter7.com
            */

            /* Steki <steki@verat.net> Thu Jan 24 17:27:18 CET 2002
             *  Added check for MD5 crypted passwords
             */

            if (strcmp(h, "crypt")&& strcmp(h, "MD5")) {
               free(h - 1);
               ldap_value_free(vals);

               return NULL;
            }

            break;
         }
     }

     /*
        No terminating brace found, or empty password.

        vol@inter7.com
     */
     if (!(*t)) {
        ldap_value_free(vals);
        return NULL;
     }
  }
  
  vpw.pw_passwd = (char *)malloc((strlen(passwd) + 1));
  if (vpw.pw_passwd == NULL) {
     free(h - 1);
     ldap_value_free(vals);
     return NULL;
  }
  
  memset((char *)vpw.pw_passwd, 0, (strlen(passwd) + 1));
  memcpy((char *)vpw.pw_passwd, (char *)(passwd), strlen(passwd));

  /*
     Old passwd pointer.
     ..and don't forget to check if you even set the pointer *smack*

     vol@inter7.com
  */
  if (h)
     free(h - 1);

  ldap_value_free(vals);
  
  vals = ldap_get_values(ld, msg, "uid");
  if (vals == NULL) {
     free(vpw.pw_passwd);
     return NULL;
  }

  vpw.pw_name = (char *)malloc((strlen(*vals) + 1));
  if (vpw.pw_name == NULL) {
     free(vpw.pw_passwd);
     ldap_value_free(vals);
     return NULL;
  }

  memset((char *)vpw.pw_name, 0, (strlen(*vals) + 1));
  memcpy((char *)vpw.pw_name, (char *)(*vals), strlen(*vals));
  ldap_value_free(vals);

  vals = ldap_get_values(ld, msg, "mailQuota");
  if (vals)
     vpw.pw_shell = (char *)malloc((strlen(*vals) + 1));
  else
     vpw.pw_shell = (char *)malloc(1); 
  
  if (vpw.pw_shell == NULL) {
     free(vpw.pw_name);
     free(vpw.pw_passwd);
 
     if (vals)
        ldap_value_free(vals);

     return NULL;
  }

  if (vals) {
     memset((char *)vpw.pw_shell, 0, (strlen(*vals) + 1));
     memcpy((char *)vpw.pw_shell, (char *)(*vals), strlen(*vals));     

     ldap_value_free(vals);
  }
  else
     *vpw.pw_shell = '\0';

  vals = ldap_get_values(ld, msg, "qmaildomain");
  if ( vals ) {
  	vpw.pw_gecos = (char *)malloc((strlen(*vals) + 1));
  	if (vpw.pw_gecos == NULL) {
     		free(vpw.pw_passwd);
     		free(vpw.pw_name);
     		free(vpw.pw_dir);
     		free(vpw.pw_shell);
     		ldap_value_free(vals);
     		return NULL;     
	}
  	memset((char *)vpw.pw_gecos, 0, (strlen(*vals) + 1));
  	memcpy((char *)vpw.pw_gecos, (char *)(*vals), strlen(*vals));
  	ldap_value_free(vals);
  }

  vals = ldap_get_values(ld, msg, "mailMessageStore");
  if ( vals ){
  	vpw.pw_dir = (char *)malloc((strlen(*vals) + 1));
  	if (vpw.pw_dir == NULL) {
    		free(vpw.pw_passwd);
    		free(vpw.pw_name);
    		free(vpw.pw_shell);
    		ldap_value_free(vals);
    		return NULL;
  	}  
  	memset((char *)vpw.pw_dir, 0, (strlen(*vals) + 1));
  	memcpy((char *)vpw.pw_dir, (char *)(*vals), strlen(*vals));
        ldap_value_free(vals);
  }

  vals = ldap_get_values(ld, msg, "qmailUID");
  if ( vals ) {
  	vpw.pw_uid = atoi(*vals);
  	ldap_value_free(vals);
  }

  vals = ldap_get_values(ld, msg, "qmailGID");
  if ( vals ) {
  	vpw.pw_gid = atoi(*vals);
  	ldap_value_free(vals);
  }

  return(&vpw);
}
void vauth_end_getall()
{
}

struct vqpasswd *vauth_getall(char *domain, int first, int sortit)
{
  int ret = 0;
  struct vqpasswd *pw = NULL;
  LDAPMessage *res = NULL;
  char *filter = NULL, **vals = NULL;
  int eret = 0;
  char *basedn = NULL;

  if (first) {
     lowerit(domain);

     ret = (32 + 1);
     eret = (strlen(VLDAP_BASEDN) - 2 + strlen(domain) + 1);

    filter = (char *)malloc(ret);
    if (filter == NULL)
       return NULL;     
  
    memset((char *)filter, 0, ret);
    basedn = (char *)malloc(eret);
    if (basedn == NULL) {
       free(filter);
       return NULL;
    } 

    memset((char *)basedn, 0, eret);

    snprintf(filter, ret, "(objectclass=qmailUser)");
    snprintf(basedn, eret, VLDAP_BASEDN, domain);

    if (ld == NULL) {
       ld = ldap_init(VLDAP_SERVER, VLDAP_PORT);
       if (ld == NULL) {
          free(filter);
          return NULL;
       }
 
       ret = ldap_simple_bind_s(ld, VLDAP_USER, VLDAP_PASSWORD);
       if (ret != LDAP_SUCCESS) {
          free(filter);
          return NULL;
       }
     }

    ret = ldap_search_s(ld, basedn, LDAP_SCOPE_SUBTREE,
                        filter, vldap_attrs, 0, &res);

    free(basedn);
    free(filter);
  
    if (ret != LDAP_SUCCESS)
       return NULL;
     
    glm = ldap_first_entry(ld, res);
    if (glm == NULL)
       return NULL;

    vals = ldap_get_values(ld, glm, "uid");
    if (vals == NULL)
       return NULL;

    pw = vauth_getpw(*vals, domain);

    return pw;
  }

  else {
    if (glm == NULL)  /* Just to be safe. (vol@inter7.com) */
       return NULL;

    res = glm;

    glm = ldap_next_entry(ld, res);
    if (glm == NULL)
       return NULL;

    vals = ldap_get_values(ld, glm, "uid");
    if (vals == NULL)
       return NULL;    
    
    pw = vauth_getpw(*vals, domain);

    ldap_value_free(vals);
    
    return pw;
  }
}

/*
   Higher-level functions no longer crypt.
   Lame.

   vol@inter7.com
*/
int vauth_adduser(char *user, char *domain, char *password, char *gecos, char *dir, int apop )
{
  char *dn = NULL;
  LDAPMod **lm = NULL; 
  char dom_dir[156];
  uid_t uid;
  gid_t gid;
  int ret = 0, vd = 0;
  int i,j;
  char *b = NULL;
  char crypted[100] = { 0 };


  if ((dir) && (*dir))
     vd = 1;

  if ( gecos==0 || gecos[0]==0) gecos=user;

  vget_assign(domain, dom_dir, 156, &uid, &gid );
  if (vd) {
     ret = strlen(dom_dir) + 5 + strlen(dir) + strlen(user);
  } else {
     ret = strlen(dom_dir) + 5 + strlen(user);
  }

  b = (char *)malloc(ret);
  if (b == NULL) return -98;
  memset((char *)b, 0, ret);
  
  if (vd) {
     snprintf(b, ret, "%s/%s/%s", dom_dir, dir, user);
  } else {
     snprintf(b, ret, "%s/%s", dom_dir, user);
  }

  dir = b;
  
  if (ld == NULL) {
     ld = ldap_init(VLDAP_SERVER, VLDAP_PORT);
     if (ld == NULL)
        return -99;
 
     ret = ldap_simple_bind_s(ld, VLDAP_USER, VLDAP_PASSWORD);
     if (ret != LDAP_SUCCESS)
        return -99;
  }

  lm = (LDAPMod **)malloc(sizeof(LDAPMod *) * 9);
  if (lm == NULL) return -98;   

  for(i=0;i<8;++i) {
    lm[i] = (LDAPMod *)malloc(sizeof(LDAPMod)); 
    if (lm[i] == NULL) {
      for(j=0;j<i;++j) free(lm[j]);
        free(lm);
        return -98;
    }
    memset((LDAPMod *)lm[i], 0, sizeof(LDAPMod));
    lm[i]->mod_op = LDAP_MOD_ADD; 
    lm[i]->mod_type = strdup(ldap_fields[i]);
    lm[i]->mod_values = (char **)malloc(sizeof(char *) * 2);
    lm[i]->mod_values[1] = NULL;
  }
  lm[8] = NULL;

  lm[0]->mod_values[0] = strdup(user);

  memset((char *)crypted, 0, 100);
  if ( password[0] == 0 ) {
    crypted[0] = 0;
  } else {
    mkpasswd3(password, crypted, 100);
  }

  lm[1]->mod_values[0] = malloc(strlen(crypted) + 7 + 1);
#ifdef MD5_PASSWORDS
  snprintf(lm[1]->mod_values[0], strlen(crypted) + 7 + 1, "{MD5}%s", crypted);
#else
  snprintf(lm[1]->mod_values[0], strlen(crypted) + 7 + 1, "{crypt}%s", crypted);
#endif

  lm[2]->mod_values[0] = malloc(10);
  if ( apop == USE_POP ) sprintf(lm[2]->mod_values[0], "%d", 1 );
  else sprintf(lm[2]->mod_values[0], "%d", 2 );

  lm[3]->mod_values[0] = malloc(10);
  sprintf(lm[3]->mod_values[0], "%d", 0);
  lm[4]->mod_values[0] = strdup(gecos);
  lm[5]->mod_values[0] = strdup(dir);
#ifdef HARD_QUOTA
  lm[6]->mod_values[0] = malloc(10); 
  sprintf(lm[6]->mod_values[0], "%s", HARD_QUOTA); 
#else
  lm[6]->mod_values[0] = strdup("NOQUOTA");
#endif
  lm[7]->mod_values[0] = strdup("qmailUser");


  ret = 4 + strlen(user) + 2 + strlen(VLDAP_BASEDN) - 2 + strlen(domain) + 1;
  b = (char *)malloc(ret);

  dn = (char *)malloc(ret);
  if (dn == NULL) {
     for(i=0;i<8;++i) { 
	free(lm[i]->mod_type);
	free(lm[i]->mod_values[0]);
     }
     free(lm);
     return -98;
  }
  
  memset((char *)dn, 0, ret);

  memset((char *)b, 0, ret);
  snprintf(b, ret, "uid=%s, %s", user, VLDAP_BASEDN);
  snprintf(dn, ret, b, domain);
  free(b);

  ret = ldap_add_s(ld, dn, lm);
 
  free(dn);
  for(i=0;i<8;++i) {
  	free(lm[i]->mod_type);
  	free(lm[i]->mod_values[0]);
  }
  free(lm);

  if (ret != LDAP_SUCCESS) {
     if (ret == LDAP_ALREADY_EXISTS) return VA_USERNAME_EXISTS;
     return -99;
  }
  return VA_SUCCESS;
}

int vauth_adddomain( char *domain )
{
  int ret = 0;
  char *dn = NULL;
  LDAPMod **lm = NULL; 

  if (ld == NULL) {
     ld = ldap_init(VLDAP_SERVER, VLDAP_PORT);
     if (ld == NULL)
        return -99;
 
     ret = ldap_simple_bind_s(ld, VLDAP_USER, VLDAP_PASSWORD);
     if (ret != LDAP_SUCCESS)
        return -99;
  }

  lm = (LDAPMod **)malloc(sizeof(LDAPMod *) * 2);
  if (lm == NULL)
     return -98;   

  lm[0] = (LDAPMod *)malloc(sizeof(LDAPMod)); 
  if (lm[0] == NULL) {
     free(lm);
     return -98;
  }

  lm[1] = (LDAPMod *)malloc(sizeof(LDAPMod)); 
  if (lm[1] == NULL) {
     free(lm[0]);
     free(lm);
     return -98;
  }

  lm[2] = NULL;

  memset((LDAPMod *)lm[0], 0, sizeof(LDAPMod));
  memset((LDAPMod *)lm[1], 0, sizeof(LDAPMod));

  lm[0]->mod_op = LDAP_MOD_ADD; 
  lm[1]->mod_op = LDAP_MOD_ADD; 

  lm[0]->mod_type = strdup("ou");
  lm[1]->mod_type = strdup("objectclass");
  
  lm[0]->mod_values = (char **)malloc(sizeof(char *) * 2);
  lm[1]->mod_values = (char **)malloc(sizeof(char *) * 2);

  lm[0]->mod_values[1] = NULL;
  lm[1]->mod_values[1] = NULL;

  lm[0]->mod_values[0] = strdup(domain);
  lm[1]->mod_values[0] = strdup("organizationalUnit");

  ret = strlen(domain) + strlen(VLDAP_BASEDN) - 2 + 1;

  dn = (char *)malloc(ret);
  if (dn == NULL) {
     free(lm[0]->mod_type);
     free(lm[1]->mod_type);
     free(lm[0]->mod_values[0]);
     free(lm[1]->mod_values[0]);
     free(lm[1]);
     free(lm[0]);
     free(lm);

     return -98;
  }
  
  memset((char *)dn, 0, ret);
  snprintf(dn, ret, VLDAP_BASEDN, domain);

  ret = ldap_add_s(ld, dn, lm);
 
  free(dn);
  free(lm[0]->mod_type);
  free(lm[1]->mod_type);
  free(lm[0]->mod_values[0]);
  free(lm[1]->mod_values[0]);
  free(lm[2]);
  free(lm[1]);
  free(lm[0]);
  free(lm);

  if (ret != LDAP_SUCCESS) {
     if (ret == LDAP_ALREADY_EXISTS) return VA_USERNAME_EXISTS;
     return -99;
  }

  return VA_SUCCESS;
}

int vauth_deldomain( char *domain )
{
  int ret = 0;
  char *dn = NULL;
  struct vqpasswd *pw = NULL;

  if (ld == NULL) {
     ld = ldap_init(VLDAP_SERVER, VLDAP_PORT);
     if (ld == NULL)
        return -99;
 
     ret = ldap_simple_bind_s(ld, VLDAP_USER, VLDAP_PASSWORD);
     if (ret != LDAP_SUCCESS)
        return -99;
  }

  ret = strlen(domain) + strlen(VLDAP_BASEDN) - 2 + 1;
  
  dn = (char *)malloc(ret);
  if (dn == NULL)
     return -98;

  memset((char *)dn, 0, ret);
  snprintf(dn, ret, VLDAP_BASEDN, domain);

  for (pw = vauth_getall(domain, 1, 0); pw; pw = vauth_getall(domain, 0, 0))
      vauth_deluser(pw->pw_name, domain);

  ret = ldap_delete_s(ld, dn);

  free(dn);

  if (ret != LDAP_SUCCESS)
     return -99;

  return VA_SUCCESS;
}

int vauth_vpasswd( char *user, char *domain, char *crypted, int apop )
{
  int ret = 0;
  struct vqpasswd *pw = NULL;

  pw = vauth_getpw(user, domain);
  if (pw == NULL)
     return VA_USER_DOES_NOT_EXIST;

  pw->pw_passwd = strdup(crypted);

  ret = vauth_setpw(pw, domain);
  
  return ret;
}

int vauth_deluser( char *user, char *domain )
{
  int ret = 0;
  char *dn = NULL;
  char *b = NULL;


  if (ld == NULL) {
     ld = ldap_init(VLDAP_SERVER, VLDAP_PORT);
     if (ld == NULL)
        return -99;
 
     ret = ldap_simple_bind_s(ld, VLDAP_USER, VLDAP_PASSWORD);
     if (ret != LDAP_SUCCESS)
        return -99;
  }

  ret = 4 + strlen(user) + 2 + strlen(VLDAP_BASEDN) - 2 + strlen(domain) + 1;

  b = (char *)malloc(ret);

  dn = (char *)malloc(ret);
  if (dn == NULL)
     return -98;  
  
  memset((char *)dn, 0, ret);
  memset((char *)b, 0, ret);
  snprintf(b, ret, "uid=%s, %s", user, VLDAP_BASEDN);
  snprintf(dn, ret, b, domain);
  free(b);

  ret = ldap_delete_s(ld, dn);

  free(dn);  

  if (ret != LDAP_SUCCESS)
     return -99;

  return VA_SUCCESS;
}

int vauth_setquota( char *username, char *domain, char *quota)
{
  int ret = 0;
  struct vqpasswd *pw = NULL;

    if ( strlen(username) > MAX_PW_NAME ) return(VA_USER_NAME_TOO_LONG);
    if ( strlen(username) == 1 ) return(VA_ILLEGAL_USERNAME);
    if ( strlen(domain) > MAX_PW_DOMAIN ) return(VA_DOMAIN_NAME_TOO_LONG);
    if ( strlen(quota) > MAX_PW_QUOTA )    return(VA_QUOTA_TOO_LONG);

  pw = vauth_getpw(username, domain);
  if (pw == NULL)
     return VA_USER_DOES_NOT_EXIST;

  pw->pw_shell = strdup(quota);

  ret = vauth_setpw(pw, domain);
  
  return ret;
}

int vauth_setpw( struct vqpasswd *inpw, char *domain ) 
{
  int ret = 0;
  char *dn = NULL;
  LDAPMod **lm = NULL;
  char *b = NULL;
  int i,j;
#ifdef SQWEBMAIL_PASS
  uid_t uid;
  gid_t gid;
#endif

    ret = vcheck_vqpw(inpw, domain);
    if ( ret != 0 ) return(ret);

  if (ld == NULL) {
     ld = ldap_init(VLDAP_SERVER, VLDAP_PORT);
     if (ld == NULL)
        return -99;
 
     ret = ldap_simple_bind_s(ld, VLDAP_USER, VLDAP_PASSWORD);
     if (ret != LDAP_SUCCESS)
        return -99;
  }

  lm = (LDAPMod **)malloc(sizeof(LDAPMod *) * 9);
  if (lm == NULL)
     return -98;   

  for(i=0;i<8;++i) {
  	lm[i] = (LDAPMod *)malloc(sizeof(LDAPMod)); 
  	if (lm[i] == NULL) {
		for(j=0;j<i;++j) free(lm[j]);
		free(lm);
		return -98;
	}
  	memset((LDAPMod *)lm[i], 0, sizeof(LDAPMod));
    lm[i]->mod_op = LDAP_MOD_REPLACE; 
    lm[i]->mod_values = (char **)malloc(sizeof(char *) * 2);
    lm[i]->mod_values[1] = NULL;
    lm[i]->mod_type = strdup(ldap_fields[i]);
  }
  lm[8] = NULL;

  lm[0]->mod_values[0] = strdup(inpw->pw_name);  

  lm[1]->mod_values[0] = malloc(strlen(inpw->pw_passwd) + 7 + 1);
  snprintf(lm[1]->mod_values[0], strlen(inpw->pw_passwd) + 7 + 1, 
	"{crypt}%s", inpw->pw_passwd);

  lm[2]->mod_values[0] = malloc(10);
  sprintf(lm[2]->mod_values[0], "%d", inpw->pw_uid);

  lm[3]->mod_values[0] = malloc(10);
  sprintf(lm[3]->mod_values[0], "%d", inpw->pw_gid);

  if ( inpw->pw_gecos == NULL) {
  	lm[4]->mod_values[0] = strdup(""); 
  } else {
  	lm[4]->mod_values[0] = strdup(inpw->pw_gecos);  
  }
  lm[5]->mod_values[0] = strdup(inpw->pw_dir);
  lm[6]->mod_values[0] = strdup(inpw->pw_shell);  
  lm[7]->mod_values[0] = strdup("qmailUser");

  ret = 4 + strlen(inpw->pw_name) + 2 + strlen(VLDAP_BASEDN) - 2 + strlen(domain) + 1;
  b = (char *)malloc(ret);

  dn = (char *)malloc(ret);
  if (dn == NULL) {
     free(lm);
     return -98;
  }
  
  memset((char *)dn, 0, ret);

  memset((char *)b, 0, ret);
  snprintf(b, ret, "uid=%s, %s", inpw->pw_name, VLDAP_BASEDN);
  snprintf(dn, ret, b, domain);
  free(b);

  ret = ldap_modify_s(ld, dn, lm);
 
  free(dn);
  for(i=0;i<8;++i) free(lm[i]);
  free(lm);

  if (ret != LDAP_SUCCESS)
     return -99;  

#ifdef SQWEBMAIL_PASS
    vget_assign(domain, NULL, 156, &uid, &gid );
    vsqwebmail_pass( inpw->pw_dir, inpw->pw_passwd, uid, gid);
#endif

  return VA_SUCCESS;
}

void vclose(void)
{
  if (ld) {
     ldap_unbind_s(ld);
     ld = NULL;
  }
}

int vread_dir_control(vdir_type *vdir, char *domain, uid_t uid, gid_t gid)
{ 
 FILE *fs;
 char dir_control_file[MAX_DIR_NAME];

    vget_assign(domain, dir_control_file, 156, NULL,NULL);
    strncpy(dir_control_file,"/.dir-control", MAX_DIR_NAME);

	if ( (fs = fopen(dir_control_file, "r")) == NULL ) {
		int i;

		vdir->cur_users = 0;
		for(i=0;i<MAX_DIR_LEVELS;++i){
			vdir->level_start[i] = 0;
			vdir->level_end[i] = MAX_DIR_LIST-1;
			vdir->level_index[i] = 0;
		}
		vdir->level_mod[0] = 0;
		vdir->level_mod[1] = 2;
		vdir->level_mod[2] = 4;
		vdir->level_cur = 0;
		vdir->level_max = MAX_DIR_LEVELS;
		vdir->the_dir[0] = 0;
		return(-1);
	} 

	fscanf(fs, "%lu\n", &vdir->cur_users);
	fscanf(fs, "%d\n", &vdir->level_cur);
	fscanf(fs, "%d\n", &vdir->level_max);
	fscanf(fs, "%d %d %d\n", 
		&vdir->level_start[0],
		&vdir->level_start[1],
		&vdir->level_start[2]);
	fscanf(fs, "%d %d %d\n", 
		&vdir->level_end[0],
		&vdir->level_end[1],
		&vdir->level_end[2]);
	fscanf(fs, "%d %d %d\n", 
		&vdir->level_mod[0],
		&vdir->level_mod[1],
		&vdir->level_mod[2]);
	fscanf(fs, "%d %d %d\n", 
		&vdir->level_index[0],
		&vdir->level_index[1],
		&vdir->level_index[2]);
	fscanf(fs, "%s\n", vdir->the_dir); 

	fclose(fs);

	return(0);
}

int vwrite_dir_control(vdir_type *vdir, char *domain, uid_t uid, gid_t gid)
{ 
 FILE *fs;
 char dir_control_file[MAX_DIR_NAME];
 char dir_control_tmp_file[MAX_DIR_NAME];

    vget_assign(domain, dir_control_file, 156, NULL,NULL);

    strncpy(dir_control_file,"/.dir-control", MAX_DIR_NAME);
    sprintf(dir_control_tmp_file,"%s/.dir-control.%d", 
        dir_control_file, getpid());

    if ( (fs = fopen(dir_control_tmp_file, "w+")) == NULL ) {
        return(-1);
    } 

    fprintf(fs, "%lu\n", vdir->cur_users);
    fprintf(fs, "%d\n", vdir->level_cur);
    fprintf(fs, "%d\n", vdir->level_max);
    fprintf(fs, "%d %d %d\n", 
        vdir->level_start[0],
        vdir->level_start[1],
        vdir->level_start[2]);
    fprintf(fs, "%d %d %d\n", 
        vdir->level_end[0],
        vdir->level_end[1],
        vdir->level_end[2]);
    fprintf(fs, "%d %d %d\n", 
        vdir->level_mod[0],
        vdir->level_mod[1],
        vdir->level_mod[2]);
    fprintf(fs, "%d %d %d\n", 
        vdir->level_index[0],
        vdir->level_index[1],
        vdir->level_index[2]);
    fprintf(fs, "%s\n", vdir->the_dir); 

    fclose(fs);

    rename( dir_control_tmp_file, dir_control_file); 

    chown(dir_control_file,uid, gid);

    return(0);
}

int vdel_dir_control(char *domain)
{
 char dir_control_file[MAX_DIR_NAME];

    vget_assign(domain, dir_control_file, 156, NULL,NULL);
    strncpy(dir_control_file,"/.dir-control", MAX_DIR_NAME);
    return(unlink(dir_control_file));
}
int vset_lastauth(char *user, char *domain, char *remoteip )
{
  return(vset_lastauth_time(user, domain, remoteip, time(NULL) ));
}

int vset_lastauth_time(char *user, char *domain, char *remoteip, time_t cur_time )
{
#ifdef ENABLE_AUTH_LOGGING
 char *tmpbuf;
 FILE *fs;
 struct vqpasswd *vpw;
 struct utimbuf ubuf;
 uid_t uid;
 gid_t gid;

	if( (vpw = vauth_getpw( user, domain )) == NULL) return(0);

	tmpbuf = malloc(MAX_BUFF);
	sprintf(tmpbuf, "%s/lastauth", vpw->pw_dir);
	if ( (fs = fopen(tmpbuf,"w+")) == NULL ) {
		free(tmpbuf);
		return(-1);
	}
	fprintf(fs, "%s", remoteip);
	fclose(fs);
        ubuf.actime = cur_time;
        ubuf.modtime = cur_time;
        utime(tmpbuf, &ubuf);
        vget_assign(domain,NULL,0,&uid,&gid);
        chown(tmpbuf,uid,gid);
	free(tmpbuf);
#else
	return(0);
#endif
}

time_t vget_lastauth( struct vqpasswd *pw, char *domain)
{
#ifdef ENABLE_AUTH_LOGGING
 char *tmpbuf;
 struct stat mystatbuf;

	tmpbuf = malloc(MAX_BUFF);
	sprintf(tmpbuf, "%s/lastauth", pw->pw_dir);
	if ( stat(tmpbuf,&mystatbuf) == -1 ) {
		free(tmpbuf);
		return(0);
	}
	free(tmpbuf);
	return(mystatbuf.st_mtime);
#else
	return(0);
#endif
}

char *vget_lastauthip( struct vqpasswd *pw, char *domain)
{
#ifdef ENABLE_AUTH_LOGGING
 static char tmpbuf[MAX_BUFF];
 FILE *fs;

   snprintf(tmpbuf, MAX_BUFF, "%s/lastauth", pw->pw_dir);
        if ( (fs=fopen(tmpbuf,"r"))==NULL) return(NULL);
        fgets(tmpbuf,MAX_BUFF,fs);
        fclose(fs);
        return(tmpbuf);
#else
   return(NULL);
#endif
}

#ifdef IP_ALIAS_DOMAINS
int vget_ip_map( char *ip, char *domain, int domain_size)
{
 FILE *fs;
 char tmpbuf[156];
 char *tmpstr;

	if ( ip == NULL || strlen(ip) <= 0 ) return(-1);

	/* open the ip_alias_map file */
	snprintf(tmpbuf, 156, "%s/%s", VPOPMAILDIR, IP_ALIAS_MAP_FILE);
	if ( (fs = fopen(tmpbuf,"r")) == NULL ) return(-1);

	while( fgets(tmpbuf, 156, fs) != NULL ) {
		tmpstr = strtok(tmpbuf, IP_ALIAS_TOKENS);
		if ( tmpstr == NULL ) continue;
		if ( strcmp(ip, tmpstr) != 0 ) continue;

		tmpstr = strtok(NULL, IP_ALIAS_TOKENS);
		if ( tmpstr == NULL ) continue;
		strncpy(domain, tmpstr, domain_size);
		fclose(fs);
		return(0);

	}
	fclose(fs);
	return(-1);
}

/* 
 * Add an ip to domain mapping
 * It will remove any duplicate entry before adding it
 *
 */
int vadd_ip_map( char *ip, char *domain)
{
 FILE *fs;
 char tmpbuf[156];

	if ( ip == NULL || strlen(ip) <= 0 ) return(-1);
	if ( domain == NULL || strlen(domain) <= 0 ) return(-10);

	vdel_ip_map( ip, domain );

	snprintf(tmpbuf, 156, "%s/%s", VPOPMAILDIR, IP_ALIAS_MAP_FILE);
	if ( (fs = fopen(tmpbuf,"a+")) == NULL ) return(-1);
	fprintf( fs, "%s %s\n", ip, domain);
	fclose(fs);

	return(0);
}

int vdel_ip_map( char *ip, char *domain) 
{
 FILE *fs;
 FILE *fs1;
 char file1[156];
 char file2[156];
 char tmpbuf[156];
 char tmpbuf1[156];
 char *ip_f;
 char *domain_f;

	if ( ip == NULL || strlen(ip) <= 0 ) return(-1);
	if ( domain == NULL || strlen(domain) <= 0 ) return(-1);

	snprintf(file1, 156, "%s/%s", VPOPMAILDIR, IP_ALIAS_MAP_FILE);
	if ( (fs = fopen(file1,"r")) == NULL ) return(-1);

	snprintf(file2, 156,
            "%s/%s.%d", VPOPMAILDIR, IP_ALIAS_MAP_FILE, getpid());
	if ( (fs1 = fopen(file2,"w")) == NULL ) {
		fclose(fs);
		return(-1);
	}

	while( fgets(tmpbuf, 156, fs) != NULL ) {
		strncpy(tmpbuf1,tmpbuf, 156);

		ip_f = strtok(tmpbuf, IP_ALIAS_TOKENS);
		if ( ip_f == NULL ) continue;

		domain_f = strtok(NULL, IP_ALIAS_TOKENS);
		if ( domain_f == NULL ) continue;

		if ( strcmp(ip, ip_f) == 0 && strcmp(domain,domain_f) == 0)
			continue;

		fprintf(fs1, tmpbuf1);

	}
	fclose(fs);
	fclose(fs1);

	if ( rename( file2, file1) < 0 ) return(-1);

	return(0);
}

int vshow_ip_map( int first, char *ip, char *domain)
{
 static FILE *fs = NULL;
 char tmpbuf[156];
 char *tmpstr;

	if ( ip == NULL ) return(-1);
	if ( domain == NULL ) return(-1);

	if ( first == 1 ) {
		if ( fs != NULL ) {
			fclose(fs);
			fs = NULL;
		}
		snprintf(tmpbuf, 156, "%s/%s", VPOPMAILDIR, IP_ALIAS_MAP_FILE);
		if ( (fs = fopen(tmpbuf,"r")) == NULL ) return(-1);
	}
	if ( fs == NULL ) return(-1);

	while (1) {
		if (fgets(tmpbuf, 156, fs) == NULL ) {
			fclose(fs);
			fs = NULL;
			return(0);
		}

		tmpstr = strtok(tmpbuf, IP_ALIAS_TOKENS);
		if ( tmpstr == NULL ) continue;
		strcpy( ip, tmpstr);

		tmpstr = strtok(NULL, IP_ALIAS_TOKENS);
		if ( tmpstr == NULL ) continue;
		strcpy( domain, tmpstr);

		return(1);
	}
	return(-1);

}
#endif
