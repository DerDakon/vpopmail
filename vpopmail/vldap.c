/* * Copyright (C) 1999-2002 Inter7 Internet Technologies, Inc.
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
#include "vlimits.h"
#include "vldap.h"

LDAP *ld = NULL;
LDAPMessage *glm = NULL;

#ifdef CLEAR_PASS
#  define NUM_LDAP_FIELDS  9
#else
#  define NUM_LDAP_FIELDS  8
#endif

char *ldap_fields[NUM_LDAP_FIELDS] = {
  "uid",			/* 0 pw_name   */ 
  "userPassword",		/* 1 pw_passwd */
  "qmailUID",			/* 2 pw_uid    */
  "qmailGID",			/* 3 pw_gid    */
  "qmaildomain",		/* 4 pw_gecos  */
  "mailMessageStore",		/* 5 pw_dir    */
  "mailQuota",			/* 6 pw_shell  */
#ifndef CLEAR_PASS
  "objectclass"            /* 7 ldap      */
#else
  "clearPassword",     /* 7 pw_clear_passwd */
  "objectclass"            /* 8 ldap      */
#endif
};

struct vqpasswd *vauth_getpw(char *user, char *domain)
{
  int ret = 0;
  size_t len = 0;
  struct vqpasswd *vpw = NULL;
  LDAPMessage *res = NULL, *msg = NULL;
  char *filter = NULL, **vals = NULL, *h = NULL, *t = NULL, *passwd = NULL;
  char *dn = NULL;
  uid_t myuid; 
  uid_t uid; 
  gid_t gid;
  struct vlimits limits;

  verrori = 0;
  lowerit(user);
  lowerit(domain);

  vget_assign(domain,NULL,0,&uid,&gid);
  
  myuid = geteuid();
  if ( myuid != 0 && myuid != uid ) {
    return(NULL);
  }
  
  if (compose_dn(&dn,domain) != 0)
  	return NULL;
  
  len = (strlen(user) + 32 + 1);
  filter = (char *)safe_malloc(len);
  memset((char *)filter, 0, len);
  snprintf(filter, len, "(&(objectclass=qmailUser)(uid=%s))", user);

  if (ld == NULL ) {
  	if (ldap_connect() != 0) {
  		safe_free((void **) &filter);
		return NULL;
	}
  }

  ret = ldap_search_s(ld, dn, LDAP_SCOPE_SUBTREE,
                      filter, vldap_attrs, 0, &res);
  
  safe_free((void **) &filter);

  if (ret != LDAP_SUCCESS ) {
  	ldap_perror(ld,"Error");
	return NULL;
  }

  msg = ldap_first_entry(ld, res);
  
  if (msg == NULL) 
	return NULL;
	
  ret = ldap_count_entries(ld, msg);
  if (ret == -1 ) {
  	ldap_perror(ld,"Error");
	return NULL;
	}

  
  /*
     Fetch userPassword first so we can make sure
     we're able to handle it's password encryption (if any)
  */
 
  vals = ldap_get_values(ld, msg, "userPassword");
  if (vals == NULL) {
  	ldap_perror(ld,"Error");
     return NULL;
	}

  t = h = NULL;

  passwd = (char *)safe_malloc((strlen(*vals) + 1));

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
  
  vpw = (struct vqpasswd *) safe_malloc(sizeof(struct vqpasswd));
  memset((struct vqpasswd *)vpw, 0, sizeof(struct vqpasswd));
  
  vpw->pw_passwd = (char *)safe_malloc((strlen(passwd) + 1));
  memset((char *)vpw->pw_passwd, 0, (strlen(passwd) + 1));
  memcpy((char *)vpw->pw_passwd, (char *)(passwd), strlen(passwd));
  
  if (vpw->pw_passwd == NULL) {
     free(h - 1);
     ldap_value_free(vals);
     return NULL;
  }
  
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
     safe_free((void **) &vpw->pw_passwd);
  	 ldap_perror(ld,"Error");
     return NULL;
  }

  vpw->pw_name = (char *)safe_malloc((strlen(*vals) + 1));

  memset((char *)vpw->pw_name, 0, (strlen(*vals) + 1));
  memcpy((char *)vpw->pw_name, (char *)(*vals), strlen(*vals));
  ldap_value_free(vals);

  vals = ldap_get_values(ld, msg, "mailQuota");
  if (vals)
     vpw->pw_shell = (char *)safe_malloc((strlen(*vals) + 1));
  else
     vpw->pw_shell = (char *)safe_malloc(1); 
  
  if (vals) {
     memset((char *)vpw->pw_shell, 0, (strlen(*vals) + 1));
     memcpy((char *)vpw->pw_shell, (char *)(*vals), strlen(*vals));     

     ldap_value_free(vals);
  }
  else {
     *vpw->pw_shell = '\0';
  	ldap_perror(ld,"Error");
	}

  vals = ldap_get_values(ld, msg, "qmaildomain");
  if ( vals ) {
  	vpw->pw_gecos = (char *)safe_malloc((strlen(*vals) + 1));
  	
	memset((char *)vpw->pw_gecos, 0, (strlen(*vals) + 1));
  	memcpy((char *)vpw->pw_gecos, (char *)(*vals), strlen(*vals));
  	ldap_value_free(vals);
  }
	else 
  		ldap_perror(ld,"Error");

  vals = ldap_get_values(ld, msg, "mailMessageStore");
  if ( vals ){
  	vpw->pw_dir = (char *)safe_malloc((strlen(*vals) + 1));
  	
	memset((char *)vpw->pw_dir, 0, (strlen(*vals) + 1));
  	memcpy((char *)vpw->pw_dir, (char *)(*vals), strlen(*vals));
        ldap_value_free(vals);
  }
	else 
  		ldap_perror(ld,"Error");

  vals = ldap_get_values(ld, msg, "qmailUID");
  if ( vals ) {
  	vpw->pw_uid = atoi(*vals);
  	ldap_value_free(vals);
  }
	else 
  		ldap_perror(ld,"Error");

  vals = ldap_get_values(ld, msg, "qmailGID");
  if ( vals ) {
  	vpw->pw_gid = atoi(*vals);
  	ldap_value_free(vals);
  }
	else 
  		ldap_perror(ld,"Error");

#ifdef CLEAR_PASS
  /* for pw_clear_passwd */
  vals = ldap_get_values(ld, msg, "clearPassword");
  if ( vals ) {
   vpw->pw_clear_passwd = (char *)safe_malloc((strlen(*vals) + 1));
   memset((char *)vpw->pw_clear_passwd, 0, (strlen(*vals) + 1));
   memcpy((char *)vpw->pw_clear_passwd, (char *)(*vals), strlen(*vals));
   ldap_value_free(vals);
  } 
#endif

  if ((! vpw->pw_gid && V_OVERRIDE)
    && (vget_limits (in_domain, &limits) == 0)) {
      vpw->pw_flags = vpw->pw_gid | vlimits_get_gid_mask (&limits);
  } else vpw->pw_flags = vpw->pw_gid;

 return vpw;

}
void vauth_end_getall()
{
}

struct vqpasswd *vauth_getall(char *domain, int first, int sortit)
{
  int ret = 0;
  size_t len = 0;
  struct vqpasswd *pw = NULL;
  LDAPMessage *res = NULL;
  char *filter = NULL, **vals = NULL;
  char *basedn = NULL;

  if (first) {
     lowerit(domain);

     len = (32 + 1);

    filter = (char *)safe_malloc(len);
  
    memset((char *)filter, 0, len);
    
	if (compose_dn(&basedn,domain) != 0)  {
		safe_free((void **) &filter);
  		return NULL;
	}

    snprintf(filter, len, "(objectclass=qmailUser)");

  if (ld == NULL ) {
  	if (ldap_connect() != 0) {
  		safe_free((void **) &filter);
  		return NULL;
		}
	}
    
	ret = ldap_search_s(ld, basedn, LDAP_SCOPE_SUBTREE,
                        filter, vldap_attrs, 0, &res);
	
    safe_free((void **) &basedn);
    safe_free((void **) &filter);

	if (ret != LDAP_SUCCESS) {
  		ldap_perror(ld,"Error");
		return NULL;
	}


 	if ( ldap_sort_entries( ld, &res, "uid", &strcasecmp ) != 0)  {
  		ldap_perror(ld,"Error");
		return NULL;
	}

 
    if (ret != LDAP_SUCCESS)
       return NULL;
     
    glm = ldap_first_entry(ld, res);
    if (glm == NULL)
       return NULL;

    vals = ldap_get_values(ld, glm, "uid");
    if (vals == NULL) {
  		ldap_perror(ld,"Error");
       return NULL;
	}

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
    if (vals == NULL) {
  		ldap_perror(ld,"Error");
       return NULL;    
	}
    
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
  char *dn_tmp = NULL;
  LDAPMod **lm = NULL; 
  char dom_dir[156];
  uid_t uid;
  gid_t gid;
  int ret = 0, vd = 0;
  int i,len;
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

  b = (char *)safe_malloc(ret);
  
  memset((char *)b, 0, ret);
  
  if (vd) {
     snprintf(b, ret, "%s/%s/%s", dom_dir, dir, user);
  } else {
     snprintf(b, ret, "%s/%s", dom_dir, user);
  }

  dir = b;
  
  if (ld == NULL ) {
  	if (ldap_connect() != 0)
  		return -99;
	}

  lm = (LDAPMod **)safe_malloc(sizeof(LDAPMod *) * (NUM_LDAP_FIELDS +1));
  
  for(i=0;i<NUM_LDAP_FIELDS;++i) {
	lm[i] = (LDAPMod *)safe_malloc(sizeof(LDAPMod)); 
    
	memset((LDAPMod *)lm[i], 0, sizeof(LDAPMod));
    lm[i]->mod_op = LDAP_MOD_ADD; 
    lm[i]->mod_type = safe_strdup(ldap_fields[i]);
    lm[i]->mod_values = (char **)safe_malloc(sizeof(char *) * 2);
    lm[i]->mod_values[1] = NULL;
  }

  lm[NUM_LDAP_FIELDS] = NULL;
  lm[0]->mod_values[0] = safe_strdup(user);

  memset((char *)crypted, 0, 100);
  if ( password[0] == 0 ) {
    crypted[0] = 0;
  } else {
    mkpasswd3(password, crypted, 100);
  }

  lm[1]->mod_values[0] = (char *) safe_malloc(strlen(crypted) + 7 + 1);
#ifdef MD5_PASSWORDS
  snprintf(lm[1]->mod_values[0], strlen(crypted) + 7 + 1, "{MD5}%s", crypted);
#else
  snprintf(lm[1]->mod_values[0], strlen(crypted) + 7 + 1, "{crypt}%s", crypted);
#endif

  lm[2]->mod_values[0] = (char *) safe_malloc(10);
  if ( apop == USE_POP ) sprintf(lm[2]->mod_values[0], "%d", 1 );
  else sprintf(lm[2]->mod_values[0], "%d", 2 );

  lm[3]->mod_values[0] = (char *) safe_malloc(10);
  sprintf(lm[3]->mod_values[0], "%d", 0);
  lm[4]->mod_values[0] = safe_strdup(gecos);
  lm[5]->mod_values[0] = safe_strdup(dir);
#ifdef HARD_QUOTA
  lm[6]->mod_values[0] = (char *) safe_malloc(10); 
  sprintf(lm[6]->mod_values[0], "%s", HARD_QUOTA); 
#else
  lm[6]->mod_values[0] = safe_strdup("NOQUOTA");
#endif
  lm[NUM_LDAP_FIELDS-1]->mod_values[0] = safe_strdup("qmailUser");
#ifdef CLEAR_PASS
  lm[7]->mod_values[0] = strdup(password);
#endif

  
  if (compose_dn(&dn_tmp,domain) != 0) {
     for(i=0;i<8;++i) { 
		safe_free((void **) &lm[i]->mod_type);
		safe_free((void **) &lm[i]->mod_values[0]);
     }
     safe_free((void **) &lm);
	 safe_free((void **) &dn);
     return -98;
  }
  
  len = 4 + strlen(user) + 2 + strlen(VLDAP_BASEDN) + 4 + strlen(domain) + 1;
  
  dn = (char *) safe_malloc(len);
	
  memset((char *)dn, 0, len);
  snprintf(dn, len, "uid=%s, %s", user, dn_tmp);
  
  safe_free((void **) &dn_tmp);

  ret = ldap_add_s(ld, dn, lm);
  safe_free((void **) &dn);

  for(i=0;i<NUM_LDAP_FIELDS;++i) {
  	safe_free((void **) &lm[i]->mod_type);
  	safe_free((void **) &lm[i]->mod_values[0]);
  }
  
  safe_free((void **) &lm);

  if (ret != LDAP_SUCCESS) {
  	 ldap_perror(ld,"Error");
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

  if (ld == NULL ) {
  	ret = ldap_connect();
  	if (ret != 0) {
  		return -99;
		/* Attention I am not quite shure, when we return NULL or -99, see above */
		}
	}

  lm = (LDAPMod **)safe_malloc(sizeof(LDAPMod *) * 2);

  lm[0] = (LDAPMod *)safe_malloc(sizeof(LDAPMod)); 

  lm[1] = (LDAPMod *)safe_malloc(sizeof(LDAPMod)); 
  lm[2] = NULL;

  memset((LDAPMod *)lm[0], 0, sizeof(LDAPMod));
  memset((LDAPMod *)lm[1], 0, sizeof(LDAPMod));

  lm[0]->mod_op = LDAP_MOD_ADD; 
  lm[1]->mod_op = LDAP_MOD_ADD; 

  lm[0]->mod_type = safe_strdup("ou");
  lm[1]->mod_type = safe_strdup("objectclass");
  
  lm[0]->mod_values = (char **)safe_malloc(sizeof(char *) * 2);
  lm[1]->mod_values = (char **)safe_malloc(sizeof(char *) * 2);

  lm[0]->mod_values[1] = NULL;
  lm[1]->mod_values[1] = NULL;

  lm[0]->mod_values[0] = safe_strdup(domain);
  lm[1]->mod_values[0] = safe_strdup("organizationalUnit");

  if (compose_dn(&dn,domain) != 0 ) {
     safe_free((void **) &lm[0]->mod_type);
     safe_free((void **) &lm[1]->mod_type);
     safe_free((void **) &lm[0]->mod_values[0]);
     safe_free((void **) &lm[1]->mod_values[0]);
     safe_free((void **) &lm[1]);
     safe_free((void **) &lm[0]);
     safe_free((void **) &lm);
	return -98;
	}

  ret = ldap_add_s(ld, dn, lm);
 
 if (ret != LDAP_SUCCESS) {
  	ldap_perror(ld,"Error");
    return -99;
	} 

  safe_free((void **) &dn);
  safe_free((void **) &lm[0]->mod_type);
  safe_free((void **) &lm[1]->mod_type);
  safe_free((void **) &lm[0]->mod_values[0]);
  safe_free((void **) &lm[1]->mod_values[0]);
  safe_free((void **) &lm[2]);
  safe_free((void **) &lm[1]);
  safe_free((void **) &lm[0]);
  safe_free((void **) &lm);

  if (ret != LDAP_SUCCESS) {
     if (ret == LDAP_ALREADY_EXISTS) return VA_USERNAME_EXISTS;
     return -99;
  }

  return VA_SUCCESS;
}

int vauth_deldomain( char *domain )
{
  int ret = 0;
  size_t len = 0;
  char *dn = NULL;
  struct vqpasswd *pw = NULL;

  if (ld == NULL ) {
  	if (ldap_connect() != 0)
  		return -99;
	}

  len = strlen(domain) + strlen(VLDAP_BASEDN) + 4 + 1;
 
  if (compose_dn(&dn,domain) != 0) 
     return -98;

  for (pw = vauth_getall(domain, 1, 0); pw; pw = vauth_getall(domain, 0, 0)) 
      vauth_deluser(pw->pw_name, domain); 
	 
  	ret = ldap_delete_s(ld, dn);
  	safe_free((void **) &dn);
	
	if (ret != LDAP_SUCCESS ) {
		ldap_perror(ld,"Error");
		return -99;
	}


  return VA_SUCCESS;
}

int vauth_vpasswd( char *user, char *domain, char *crypted, int apop )
{
  int ret = 0;
  struct vqpasswd *pw = NULL;

  pw = vauth_getpw(user, domain);
  if (pw == NULL)
     return VA_USER_DOES_NOT_EXIST;

  pw->pw_passwd = safe_strdup(crypted);

  ret = vauth_setpw(pw, domain);
  
  return ret;
}

int vauth_deluser( char *user, char *domain )
{
  int ret = 0;
  size_t len = 0;
  char *dn = NULL;
  char *dn_tmp = NULL;


  if (ld == NULL ) {
  	if (ldap_connect() != 0)
  		return -99;
	}

  len = 4 + strlen(user) + 2 + strlen(VLDAP_BASEDN) + 4 + strlen(domain) + 1;

  if (compose_dn(&dn_tmp,domain) != 0)
  	return -98;

  dn = (char *)safe_malloc(len);
  memset((char *)dn, 0, len);
  
  snprintf(dn, len, "uid=%s, %s", user, dn_tmp);
  safe_free((void **) &dn_tmp);

  ret = ldap_delete_s(ld, dn);

  safe_free((void **) &dn);  

  if (ret != LDAP_SUCCESS) {
  	ldap_perror(ld,"Error");
     return -99;
	}

  return VA_SUCCESS;
}

int vauth_setquota( char *username, char *domain, char *quota)
{
  int ret = 0;
  struct vqpasswd *pw = NULL;

    if ( strlen(username) > MAX_PW_NAME ) return(VA_USER_NAME_TOO_LONG);
#ifdef USERS_BIG_DIR
    if ( strlen(username) == 1 ) return(VA_ILLEGAL_USERNAME);
#endif
    if ( strlen(domain) > MAX_PW_DOMAIN ) return(VA_DOMAIN_NAME_TOO_LONG);
    if ( strlen(quota) > MAX_PW_QUOTA )    return(VA_QUOTA_TOO_LONG);

  pw = vauth_getpw(username, domain);
  if ( (pw == NULL) && (verrori != 0)) 
  	 return verrori;
  else if ( pw == NULL )
     return VA_USER_DOES_NOT_EXIST;

  pw->pw_shell = safe_strdup(quota);
  
  ret = vauth_setpw(pw, domain);
  
  return ret;
}

int vauth_setpw( struct vqpasswd *inpw, char *domain ) 
{
  int ret = 0;
  size_t len = 0;
  char *dn = NULL;
  char *dn_tmp = NULL;
  LDAPMod **lm = NULL;
  int i;
#ifdef SQWEBMAIL_PASS
  uid_t uid;
  gid_t gid;
#endif
    ret = vcheck_vqpw(inpw, domain);
    if ( ret != 0 ) { return(ret); }
  
  if (ld == NULL ) {
  	if (ldap_connect() != 0)
  		return -99;
	}

  lm = (LDAPMod **)malloc(sizeof(LDAPMod *) * NUM_LDAP_FIELDS + 1);
  for(i=0;i<NUM_LDAP_FIELDS;++i) {
  	lm[i] = (LDAPMod *)safe_malloc(sizeof(LDAPMod)); 
  	memset((LDAPMod *)lm[i], 0, sizeof(LDAPMod));
    lm[i]->mod_op = LDAP_MOD_REPLACE; 
    lm[i]->mod_values = (char **)safe_malloc(sizeof(char *) * 2);
    lm[i]->mod_values[1] = NULL;
    lm[i]->mod_type = safe_strdup(ldap_fields[i]);
  }
  lm[NUM_LDAP_FIELDS] = NULL;

  lm[0]->mod_values[0] = safe_strdup(inpw->pw_name);  

  lm[1]->mod_values[0] = safe_malloc(strlen(inpw->pw_passwd) + 7 + 1);
#ifdef MD5_PASSWORDS
  snprintf(lm[1]->mod_values[0], strlen(inpw->pw_passwd) + 7 + 1, "{MD5}%s", inpw->pw_passwd);
#else
  snprintf(lm[1]->mod_values[0], strlen(inpw->pw_passwd) + 7 + 1, "{crypt}%s", inpw->pw_passwd);
#endif

  lm[2]->mod_values[0] = (char *)safe_malloc(10);
  sprintf(lm[2]->mod_values[0], "%d", inpw->pw_uid);

  lm[3]->mod_values[0] = (char *) safe_malloc(10);
  sprintf(lm[3]->mod_values[0], "%d", inpw->pw_gid);

  if ( inpw->pw_gecos == NULL) {
  	lm[4]->mod_values[0] = safe_strdup(""); 
  } else {
  	lm[4]->mod_values[0] = safe_strdup(inpw->pw_gecos);  
  }
  lm[5]->mod_values[0] = safe_strdup(inpw->pw_dir);
  lm[6]->mod_values[0] = safe_strdup(inpw->pw_shell);  
#ifdef CLEAR_PASS
  lm[7]->mod_values[0] = safe_strdup(inpw->pw_clear_passwd);
#endif
  lm[NUM_LDAP_FIELDS-1]->mod_values[0] = strdup("qmailUser");

  if (compose_dn(&dn_tmp,domain) != 0 ) {
     safe_free((void **) &lm);
     return -98;
  }

  len = 4 + strlen(inpw->pw_name) + 2 + strlen(VLDAP_BASEDN) + 4 + strlen(domain) + 1;
  dn = (char *) safe_malloc (len);
  memset((char *)dn, 0, len);
  
  snprintf(dn, len, "uid=%s, %s", inpw->pw_name, dn_tmp);

  ret = ldap_modify_s(ld, dn, lm);
  safe_free((void **) &dn);
  
  for(i=0;i<NUM_LDAP_FIELDS;++i) 
  	safe_free((void **) &lm);

  if (ret != LDAP_SUCCESS) {
  	 ldap_perror(ld,"Error");
     return -99; 	 
	}
/* MARK */
#ifdef SQWEBMAIL_PASS
    vget_assign(domain, NULL, 0, &uid, &gid );
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

int vset_lastauth_time(char *user, char *domain, char *remoteip, time_t cur_time )
{
#ifdef ENABLE_AUTH_LOGGING
 char *tmpbuf;
 FILE *fs;
 struct vqpasswd *vpw;
 struct utimbuf ubuf;
 uid_t uid;
 gid_t gid;

	if ((vpw = vauth_getpw( user, domain )) == NULL) return (0);

	tmpbuf = (char *) safe_malloc(MAX_BUFF);
	sprintf(tmpbuf, "%s/lastauth", vpw->pw_dir);
	if ( (fs = fopen(tmpbuf,"w+")) == NULL ) {
		safe_free((void **) &tmpbuf);
		return(-1);
	}
	fprintf(fs, "%s", remoteip);
	fclose(fs);
        ubuf.actime = cur_time;
        ubuf.modtime = cur_time;
        utime(tmpbuf, &ubuf);
        vget_assign(domain,NULL,0,&uid,&gid);
        chown(tmpbuf,uid,gid);
	safe_free((void **) &tmpbuf);
#endif
	return(0);
}

int vset_lastauth(char *user, char *domain, char *remoteip )
{
  return(vset_lastauth_time(user, domain, remoteip, time(NULL) ));
}

time_t vget_lastauth( struct vqpasswd *pw, char *domain)
{
#ifdef ENABLE_AUTH_LOGGING
 char *tmpbuf;
 struct stat mystatbuf;

	tmpbuf = (char *) safe_malloc(MAX_BUFF);
	sprintf(tmpbuf, "%s/lastauth", pw->pw_dir);
	if ( stat(tmpbuf,&mystatbuf) == -1 ) {
		safe_free((void **) &tmpbuf);
		return(0);
	}
	safe_free((void **) &tmpbuf);
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

int compose_dn (char **dn, char *domain)
{
    size_t len = 0;
  
  	len = strlen(domain) + strlen(VLDAP_BASEDN) + 5;
	
	*dn = (char *)safe_malloc(len);
  	memset((char *)*dn, 0, len);

  	snprintf(*dn,len,"ou=%s,%s",domain,VLDAP_BASEDN);
 
  return 0;
 
}

int ldap_connect ()
{
	int ret = 0;
  	/* Set verror here and unset it when successful, is ok, because if one of these
	three steps fail the whole auth_connection failed */
	verrori = VA_NO_AUTH_CONNECTION;
		
	ld = ldap_init(VLDAP_SERVER, VLDAP_PORT);
    if (ld == NULL) {
		ldap_perror(ld,"Failed to inititialize LDAP-Connection");
    	return -99;
	}
    ret = ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &ldapversion );
	if (ret != LDAP_OPT_SUCCESS) {
		ldap_perror(ld,"Failed to set LDAP-Option");
		return -99;
	}
    ret = ldap_simple_bind_s(ld, VLDAP_USER, VLDAP_PASSWORD);
	if (ret != LDAP_SUCCESS) {
		ldap_perror(ld,"Error");
		return (VA_NO_AUTH_CONNECTION);
	}
	
  	verrori = 0;
	return VA_SUCCESS;
}

void safe_free (void **p)
{
  if (*p)
  {
    free (*p); 
    *p = 0;
  }
}


char *safe_strdup (const char *s)
{
  char *p;
  size_t l;

  if (!s || !*s)
    return 0;
  l = strlen (s) + 1;
  p = (char *)safe_malloc (l);
  memcpy (p, s, l);
  return (p);
}


void *safe_malloc (size_t siz)
{
  void *p;

  if (siz == 0)
    return 0;
  if ((p = (void *) malloc (siz)) == 0) 
  {
     printf("No more memory...exiting\n");
    exit (1);
  }
  return (p);
}

int vauth_crypt(char *user,char *domain,char *clear_pass,struct vqpasswd *vpw)
{
  if ( vpw == NULL ) return(-1);

  return(strcmp(crypt(clear_pass,vpw->pw_passwd),vpw->pw_passwd));
}
