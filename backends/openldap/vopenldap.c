/*
   $Id$
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <utime.h>
#include <unistd.h>
#include <errno.h>
#include <ldap.h>
#include "config.h"
#include "vauth.h"
#include "vpopmail.h"
#include "md5.h"
#include "base64.h"
#include "vopenldap.h"

#ifndef PATH_MAX
   #define PATH_MAX 256
#endif

#define DN_SIZE 1024
#define FILTER_SIZE DN_SIZE

/*
   Attributes to return about a user
*/

static char *user_attrs[] = {
   "uid",
   "pw-uid",
   "pw-gid",
   "pw-dir",
   "cn",
   "userPassword",
   "pw-shell",
   "pw-clear-passwd",
   NULL
};

struct ldap_mods {
   int op,
	   mods;

   LDAPMod **attrs;
};

static struct vqpasswd g_pw;
static LDAP *ldap = NULL;
static struct ldap_mods ldap_mods;
static const char *basedn = "ou=vpopmail,dc=inter7,dc=com";
static const char *binddn = "cn=Manager,dc=inter7,dc=com";
static const char *bindpw = "secret";

void vvclose(void);
static int create_dn(char *, int, const char *, const char *);
static void mod_init(int);
static void mod_add(int, const char *, const char *);
static int mod_run(const char *);
static void use_user_result(struct vqpasswd *, LDAPMessage *);
static void free_user_result(struct vqpasswd *);
static void parse_gecos(int, const char *);
static int password_scheme_crypt(const char *, char *, int);
static int password_scheme_smd5(const char *, const char *, char *, int);
static int password_scheme_smd5_decode_salt(const char *, char *, int);

/*
   vpopmail authentication module exports
*/

const char auth_module_name[] = "openldap";
const char *auth_module_features[] = {
#ifdef IP_ALIAS_DOMAINS
   "IP_ALIAS_DOMAINS",
#endif
#ifdef ENABLE_AUTH_LOGGING
   "AUTH_LOGGING",
#endif
   NULL
};

/*
   Return a user entry from under a domain
*/

struct vqpasswd *auth_getpw(char *user, char *domain)
{
   int ret = 0;
   char dn[DN_SIZE] = { 0 };
   LDAPMessage *res = NULL, *msg = NULL;

   /*
	  Clear user structure
   */

   free_user_result(&g_pw);

   /*
	  Support default domain
   */

   vset_default_domain(domain);

   /*
	  Generate dn
   */

   ret = create_dn(dn, sizeof(dn), user, domain);
   if (!ret) {
	  fprintf(stderr, "auth_getpw: create_dn failed\n");
	  return NULL;
   }

   /*
	  Search
   */

   ret = ldap_search_ext_s(ldap, dn, LDAP_SCOPE_BASE, "(objectClass=vpopmail)", user_attrs, 0, NULL, NULL, NULL, 0, &res);
   if (ret != LDAP_SUCCESS) {
	  if (ret == LDAP_NO_SUCH_OBJECT)
		 return NULL;

	  fprintf(stderr, "auth_getpw: ldap_search_ext_s failed: %s\n", ldap_err2string(ret));
	  return NULL;
   }

   /*
	  Get result
   */

   msg = ldap_first_entry(ldap, res);
   if (msg == NULL) {
	  fprintf(stderr, "auth_getpw: ldap_first_entry failed\n");
	  return NULL;
   }

   /*
	  Fill in the structure
   */

   use_user_result(&g_pw, msg);

   /*
	  Return it
   */

   return &g_pw;
}

void auth_end_getall()
{
}

/*
   Return all user entries under a domain
*/

struct vqpasswd *auth_getall(char *domain, int first, int sortit)
{
   int ret = 0;
   char dn[DN_SIZE] = { 0 };
   static LDAPMessage *msg = NULL;
   char **val = NULL;

   if (domain == NULL)
	  return NULL;

   if (first) {
	  /*
		 Generate dn
	  */

	  ret = create_dn(dn, sizeof(dn), NULL, domain);
	  if (!ret)
		 return NULL;

	  /*
		 Search
		 objectClass must be set here because valias objects exist in the same scope
	  */

	  ret = ldap_search_ext_s(ldap, dn, LDAP_SCOPE_ONELEVEL, "(objectClass=vpopmail)", user_attrs, 0, NULL, NULL, NULL, 0, &msg);
	  if (ret != LDAP_SUCCESS) {
		 if (ret == LDAP_NO_SUCH_OBJECT)
			return NULL;

		 fprintf(stderr, "auth_getpw: ldap_search_ext_s failed: %s\n", ldap_err2string(ret));
		 return NULL;
	  }

	  /*
		 XXX Sort results
	  */

	  if (sortit) {
	  }

	  /*
		 Get result
	  */

	  msg = ldap_first_entry(ldap, msg);
   }

   else {
	  if (msg == NULL)
		 return NULL;

	  /*
		 Get next result
	  */

	  msg = ldap_next_entry(ldap, msg);
   }

   /*
	  Out of results
   */

   if (msg == NULL)
	  return NULL;

   /*
	  Fill vqpasswd structure
   */

   free_user_result(&g_pw);
   use_user_result(&g_pw, msg);

   /*
	  Return it
   */

   return &g_pw;
}

/*
   Add user to an existing domain
*/

int auth_adduser(char *user, char *domain, char *password, char *gecos, char *dir, int apop)
{
   int ret = 0;
   struct vqpasswd *pw = NULL;
   char dn[DN_SIZE] = { 0 }, email[1024] = { 0 }, *p = NULL, name[512] = { 0 }, epass[128] = { 0 },
		pw_dir[PATH_MAX] = { 0 }, dom_dir[PATH_MAX] = { 0 };

   if ((user == NULL) || (domain == NULL) || (password == NULL) || (dir == NULL))
	  return VA_NULL_POINTER;

   /*
	  Check if user exists
   */

   pw = auth_getpw(user, domain);
   if (pw)
	  return VA_USERNAME_EXISTS;

   /*
	  Generate dn
   */

   ret = create_dn(dn, sizeof(dn), user, domain);
   if (!ret)
	  return VA_INTERNAL_BUFFER_EXCEEDED;

   /*
	  Generate user path
   */

   if (vget_assign(domain, dom_dir, sizeof(dom_dir), NULL, NULL) == NULL)
	  return VA_DOMAIN_DOES_NOT_EXIST;

   if (*dir)
	  ret = snprintf(pw_dir, sizeof(pw_dir), "%s/%s/%s", dom_dir, dir, user);
   else
	  ret = snprintf(pw_dir, sizeof(pw_dir), "%s/%s", dom_dir, user);

   if (ret >= sizeof(pw_dir))
	  return VA_INTERNAL_BUFFER_EXCEEDED;

   /*
	  Build modification
   */

   mod_init(LDAP_MOD_ADD);
   mod_add(LDAP_MOD_ADD, "objectClass", "vpopmail");
   mod_add(LDAP_MOD_ADD, "uid", user);

   ret = snprintf(email, sizeof(email), "%s@%s", user, domain);
   if (ret >= sizeof(email))
	  return VA_INTERNAL_BUFFER_EXCEEDED;

   mod_add(LDAP_MOD_ADD, "mail", email);
   mod_add(LDAP_MOD_ADD, "pw-uid", "0");
   mod_add(LDAP_MOD_ADD, "pw-gid", "0");
   mod_add(LDAP_MOD_ADD, "pw-dir", pw_dir);
   mod_add(LDAP_MOD_ADD, "pw-shell", "NOQUOTA");

   /*
	  Generate hashed password
   */

   ret = password_scheme_smd5(password, NULL, epass, sizeof(epass));
   if (ret != VA_SUCCESS)
	  return ret;

   /*
	  Set password
   */

   mod_add(LDAP_MOD_ADD, "userPassword", epass);
   mod_add(LDAP_MOD_ADD, "pw-clear-passwd", password);
   
   /*
	  Parse the GECOS
   */

   parse_gecos(LDAP_MOD_ADD, gecos);

   /*
	  Run the addition
   */

   ret = mod_run(dn);
   if (ret != LDAP_SUCCESS) {
	  fprintf(stderr, "auth_adduser: %s\n", ldap_err2string(ret));
	  return VA_QUERY_FAILED;
   }

   return VA_SUCCESS;
}

/*
   Add a new domain entry
*/

int auth_adddomain(char *domain)
{
   int ret = 0;
   char dn[DN_SIZE] = { 0 };

   if (domain == NULL)
	  return VA_NULL_POINTER;

   /*
	  Generate dn
   */

   ret = create_dn(dn, sizeof(dn), NULL, domain);
   if (!ret)
	  return VA_INTERNAL_BUFFER_EXCEEDED;

   /*
	  Build modifications
   */

   mod_init(LDAP_MOD_ADD);
   mod_add(LDAP_MOD_ADD, "o", domain);
   mod_add(LDAP_MOD_ADD, "objectClass", "organization");

   /*
	  Run
   */

   ret = mod_run(dn);
   if (ret != LDAP_SUCCESS) {
	  fprintf(stderr, "auth_adddomain: %s\n", ldap_err2string(ret));
	  return VA_QUERY_FAILED;
   }

   return VA_SUCCESS;
}

/*
   Delete a domain and all its users
*/

int auth_deldomain(char *domain)
{
   int ret = 0, first = 0;
   char dn[1024] = { 0 };
   struct vqpasswd *pw = NULL;

   if (domain == NULL)
	  return VA_NULL_POINTER;

   /*
	  Delete all user entries under the domain
   */

   for (pw = auth_getall(domain, 1, 0); pw; pw = auth_getall(domain, 0, 0))
	  auth_deluser(pw->pw_name, domain);

   /*
	  Delete domain entry
   */

   ret = create_dn(dn, sizeof(dn), NULL, domain);
   if (!ret)
	  return VA_INTERNAL_BUFFER_EXCEEDED;

   mod_init(LDAP_MOD_DELETE);
   ret = mod_run(dn);
   if (ret != LDAP_SUCCESS) {
	  fprintf(stderr, "auth_deldomain: %s\n", ldap_err2string(ret));
	  return VA_QUERY_FAILED;
   }

#ifdef VALIAS
   valias_delete_domain(domain);
#endif

   return VA_SUCCESS;
}

/*
   Set a user's encrypted password
*/

int auth_vpasswd(char *user, char *domain, char *crypted, int apop)
{
   struct vqpasswd *pw = NULL;

   if ((user == NULL) || (domain == NULL) || (crypted == NULL))
	  return VA_NULL_POINTER;

   /*
	  Get user
   */

   pw = auth_getpw(user, domain);
   if (pw == NULL)
	  return VA_USER_DOES_NOT_EXIST;

   /*
	  Set field
   */

   if (pw->pw_passwd)
	  free(pw->pw_passwd);

   pw->pw_passwd = strdup(crypted);
   if (pw->pw_passwd == NULL)
	  return VA_MEMORY_ALLOC_ERR;

   /*
	  Modify database
   */

   return auth_setpw(pw, domain);
}

/*
   Delete a user entry from under a domain
*/

int auth_deluser(char *user, char *domain)
{
   int ret = 0;
   char dn[DN_SIZE] = { 0 };

   if ((user == NULL) || (domain == NULL))
	  return VA_NULL_POINTER;

   /*
	  Generate dn
   */

   ret = create_dn(dn, sizeof(dn), user, domain);
   if (!ret)
	  return VA_INTERNAL_BUFFER_EXCEEDED;

   /*
	  Set up modifications and run deletion
   */

   mod_init(LDAP_MOD_DELETE);
   ret = mod_run(dn);
   if (ret != LDAP_SUCCESS) {
	  fprintf(stderr, "auth_deluser: %s\n", ldap_err2string(ret));
	  return VA_QUERY_FAILED;
   }

   return VA_SUCCESS;
}


int auth_setquota(char *username, char *domain, char *quota)
{
   int ret = 0;
   struct vqpasswd *pw = NULL;
   
   if ((username == NULL) || (domain == NULL) || (quota == NULL))
	  return VA_NULL_POINTER;

   /*
	  Get user
   */

   pw = auth_getpw(username, domain);
   if (pw == NULL)
	  return VA_USER_DOES_NOT_EXIST;

   /*
	  Change quota field
   */

   if (pw->pw_shell)
	  free(pw->pw_shell);

   pw->pw_shell = strdup(quota);
   if (pw->pw_shell == NULL)
	  return VA_MEMORY_ALLOC_ERR;

   /*
	  Modify database
   */

   ret = auth_setpw(pw, domain);
   if (ret != VA_SUCCESS)
	  return ret;

   return VA_SUCCESS;
}

/*
   Modify existing user entry
*/

int auth_setpw(struct vqpasswd *inpw, char *domain)
{
   int ret = 0;
   char dn[DN_SIZE] = { 0 }, num[30] = { 0 };

   if ((inpw == NULL) || (domain == NULL) || (inpw->pw_name == NULL))
	  return VA_NULL_POINTER;

   /*
	  Get DN
   */

   ret = create_dn(dn, sizeof(dn), inpw->pw_name, domain);
   if (!ret)
	  return VA_INTERNAL_BUFFER_EXCEEDED;

   /*
	  Set up modifications
   */

   mod_init(LDAP_MOD_REPLACE);

   ret = snprintf(num, sizeof(num), "%d", inpw->pw_uid);
   if (ret >= sizeof(num))
	  return VA_INTERNAL_BUFFER_EXCEEDED;

   mod_add(LDAP_MOD_REPLACE, "pw-uid", num);

   ret = snprintf(num, sizeof(num), "%d", inpw->pw_gid);
   if (ret >= sizeof(num))
	  return VA_INTERNAL_BUFFER_EXCEEDED;

   mod_add(LDAP_MOD_REPLACE, "pw-gid", num);

   mod_add(LDAP_MOD_REPLACE, "pw-dir", inpw->pw_dir);
   mod_add(LDAP_MOD_REPLACE, "pw-shell", inpw->pw_shell);
   mod_add(LDAP_MOD_REPLACE, "userPassword", inpw->pw_passwd);

   parse_gecos(LDAP_MOD_REPLACE, inpw->pw_gecos);

   /*
	  Run the addition
   */

   ret = mod_run(dn);
   if (ret != LDAP_SUCCESS) {
	  fprintf(stderr, "auth_setpw: %s\n", ldap_err2string(ret));
	  return VA_QUERY_FAILED;
   }

   return VA_SUCCESS;
}

/*
   Make connection to LDAP server
*/

int auth_open(int will_update)
{
   int ret = 0;

   /*
	  Initialize static values
   */

   memset(&g_pw, 0, sizeof(g_pw));

   /*
	  Initialize LDAP state
   */

   ldap = NULL;
   ldap_mods.mods = 0;
   ldap_mods.attrs = NULL;

   /*
	  Connect
   */

   ret = ldap_initialize(&ldap, "ldap://localhost:389/");
   if (ldap == NULL) {
	  fprintf(stderr, "ldap_initialize failed: %d\n", errno);
	  return VA_NO_AUTH_CONNECTION;
   }

   /*
	  LDAP Version 3
   */

   ret = 3;
   ret = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ret);
   if (ret != LDAP_SUCCESS)
	  fprintf(stderr, "auth_open: warning: ldap_set_option: LDAP_OPT_PROTOCOL_VERSION failed\n");

   /*
	  Bind
   */

   ret = ldap_simple_bind_s(ldap, binddn, bindpw);
   if (ret != LDAP_SUCCESS) {
	  fprintf(stderr, "ldap_simple_bind_s failed: %s\n", ldap_err2string(ret));
	  vvclose();
	  return VA_NO_AUTH_CONNECTION;
   }

   return 0;
}

/*
   Close database connection
*/

void vvclose(void)
{
   mod_init(LDAP_MOD_ADD);

   if (ldap) {
	  ldap_unbind_s(ldap);
	  ldap = NULL;
   }
}

char *dc_filename(char *domain, uid_t uid, gid_t gid)
{
   int ret = 0;
   uid_t c_uid = -1;
 static char dir_control_file[MAX_DIR_NAME];
 struct passwd *pw;

    ret = vpopmail_uidgid(&c_uid, NULL);
	if (!ret) {
	   fprintf(stderr, "dc_filename: vpopmail_uidgid failed\n");
	   return "";
	}

    /* if we are lucky the domain is in the assign file */
    if ( vget_assign(domain,dir_control_file,MAX_DIR_NAME,NULL,NULL)!=NULL ) {
        strncat(dir_control_file, "/.dir-control", MAX_DIR_NAME);

    /* it isn't in the assign file so we have to get it from /etc/passwd */
    } else {

        /* save some time if this is the vpopmail user */
        if ( uid == c_uid) {
            strncpy(dir_control_file, VPOPMAIL_DIR_DOMAINS, MAX_DIR_NAME);

        /* for other users, look them up in /etc/passwd */
        } else if ( (pw=getpwuid(uid))!=NULL ) {
            strncpy(dir_control_file, pw->pw_dir, MAX_DIR_NAME);

        /* all else fails return a blank string */
        } else {
            return("");
        }

        /* stick on the rest of the path */
        strncat(dir_control_file, "/.dir-control", MAX_DIR_NAME);
    }
    return(dir_control_file);
}

int read_dir_control(vdir_type *vdir, char *domain, uid_t uid, gid_t gid)
{
 FILE *fs;
 char dir_control_file[MAX_DIR_NAME];
 int i;

    strncpy(dir_control_file,dc_filename(domain, uid, gid),MAX_DIR_NAME);


    if ( (fs = fopen(dir_control_file, "r")) == NULL ) {
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

    fgets(dir_control_file, MAX_DIR_NAME, fs );
    vdir->cur_users = atol(dir_control_file);

    fgets(dir_control_file, MAX_DIR_NAME, fs );
    vdir->level_cur = atoi(dir_control_file);

    fgets(dir_control_file, MAX_DIR_NAME, fs );
    vdir->level_max = atoi(dir_control_file);

    fgets(dir_control_file, MAX_DIR_NAME, fs );
    vdir->level_start[0] = atoi(dir_control_file);
    for(i=0;dir_control_file[i]!=' ';++i); ++i;
    vdir->level_start[1] = atoi(&dir_control_file[i]);
    for(i=0;dir_control_file[i]!=' ';++i); ++i;
    vdir->level_start[2] = atoi(&dir_control_file[i]);

    fgets(dir_control_file, MAX_DIR_NAME, fs );
    vdir->level_end[0] = atoi(dir_control_file);
    for(i=0;dir_control_file[i]!=' ';++i); ++i;
    vdir->level_end[1] = atoi(&dir_control_file[i]);
    for(i=0;dir_control_file[i]!=' ';++i); ++i;
    vdir->level_end[2] = atoi(&dir_control_file[i]);

    fgets(dir_control_file, MAX_DIR_NAME, fs );
    vdir->level_mod[0] = atoi(dir_control_file);
    for(i=0;dir_control_file[i]!=' ';++i); ++i;
    vdir->level_mod[1] = atoi(&dir_control_file[i]);
    for(i=0;dir_control_file[i]!=' ';++i); ++i;
    vdir->level_mod[2] = atoi(&dir_control_file[i]);

    fgets(dir_control_file, MAX_DIR_NAME, fs );
    vdir->level_index[0] = atoi(dir_control_file);
    for(i=0;dir_control_file[i]!=' ';++i); ++i;
    vdir->level_index[1] = atoi(&dir_control_file[i]);
    for(i=0;dir_control_file[i]!=' ';++i); ++i;
    vdir->level_index[2] = atoi(&dir_control_file[i]);

    fgets(dir_control_file, MAX_DIR_NAME, fs );
    for(i=0;dir_control_file[i]!=0;++i) {
        if (dir_control_file[i] == '\n') {
            dir_control_file[i] = 0;
        }
    }

    fgets(dir_control_file, MAX_DIR_NAME, fs );
    for(i=0;dir_control_file[i]!=0;++i) {
        if (dir_control_file[i] == '\n') {
            dir_control_file[i] = 0;
        }
    }
    strncpy(vdir->the_dir, dir_control_file, MAX_DIR_NAME);

    fclose(fs);

    return(0);
}

int write_dir_control(vdir_type *vdir, char *domain, uid_t uid, gid_t gid)
{
 FILE *fs;
 char dir_control_file[MAX_DIR_NAME];
 char dir_control_tmp_file[MAX_DIR_NAME];

    strncpy(dir_control_file,dc_filename(domain, uid, gid),MAX_DIR_NAME);
    snprintf(dir_control_tmp_file, MAX_DIR_NAME,
        "%s.%d", dir_control_file, getpid());

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

int del_dir_control(char *domain)
{
   char dir_control_file[MAX_DIR_NAME];

   vget_assign(domain, dir_control_file, sizeof(dir_control_file), NULL,NULL);
   strncat(dir_control_file, "/.dir-control", MAX_DIR_NAME - strlen(dir_control_file));

   return(unlink(dir_control_file));
}

int set_lastauth_time(char *user, char *domain, char *remoteip, time_t cur_time ) {
    FILE *fs;
    struct vqpasswd *vpw;
    struct utimbuf ubuf;
	char fn[PATH_MAX] = { 0 };
    uid_t uid;
    gid_t gid;

    if ((vpw = auth_getpw( user, domain )) == NULL)
        return (0);

    snprintf(fn, sizeof(fn), "%s/lastauth", vpw->pw_dir);
    if ((fs = fopen(fn,"w+")) == NULL)
        return(-1);

	if (remoteip)
	   fprintf(fs, "%s", remoteip);

    fclose(fs);
    ubuf.actime = cur_time;
    ubuf.modtime = cur_time;
    utime(fn, &ubuf);
    vget_assign(domain,NULL,0,&uid,&gid);
    chown(fn,uid,gid);
    return(0);
}

int set_lastauth(char *user, char *domain, char *remoteip ) {
    return(set_lastauth_time(user, domain, remoteip, time(NULL) ));
}

time_t get_lastauth( struct vqpasswd *pw, char *domain) {
    struct stat mystatbuf;
    char tmpbuf[PATH_MAX] = { 0 };

    snprintf(tmpbuf, sizeof(tmpbuf), "%s/lastauth", pw->pw_dir);
    if (stat(tmpbuf,&mystatbuf) == -1)
        return(0);

    return(mystatbuf.st_mtime);
}

char *get_lastauthip( struct vqpasswd *pw, char *domain) {
    static char tmpbuf[MAX_BUFF];
    FILE *fs;

    snprintf(tmpbuf, MAX_BUFF, "%s/lastauth", pw->pw_dir);
    if ( (fs=fopen(tmpbuf,"r"))==NULL)
        return(NULL);

    fgets(tmpbuf,MAX_BUFF,fs);
    fclose(fs);
    return(tmpbuf);
}

#ifdef IP_ALIAS_DOMAINS
int get_ip_map( char *ip, char *domain, int domain_size) {
    FILE *fs;
    char tmpbuf[156];
    char *tmpstr;

    if ( ip == NULL || strlen(ip) <= 0 )
        return(-1);

    /* open the ip_alias_map file */
    snprintf(tmpbuf, 156, "%s/%s", VPOPMAIL_DIR_ETC, IP_ALIAS_MAP_FILE);
    if ( (fs = fopen(tmpbuf,"r")) == NULL )
        return(-1);

    while( fgets(tmpbuf, 156, fs) != NULL ) {
        tmpstr = strtok(tmpbuf, IP_ALIAS_TOKENS);
        if ( tmpstr == NULL )
            continue;
        if ( strcmp(ip, tmpstr) != 0 )
            continue;

        tmpstr = strtok(NULL, IP_ALIAS_TOKENS);
        if ( tmpstr == NULL )
            continue;
        strncpy(domain, tmpstr, domain_size);
        fclose(fs);
        return(0);

    }
    fclose(fs);
    return(-1);
}

/***************************************************************************/

/*
 * Add an ip to domain mapping
 * It will remove any duplicate entry before adding it
 *
 */
int add_ip_map( char *ip, char *domain) {
    FILE *fs;
    char tmpbuf[156];

    if ( ip == NULL || strlen(ip) <= 0 )
        return(-1);
    if ( domain == NULL || strlen(domain) <= 0 )
        return(-10);

    del_ip_map( ip, domain );

    snprintf(tmpbuf, 156, "%s/%s", VPOPMAIL_DIR_ETC, IP_ALIAS_MAP_FILE);
    if ( (fs = fopen(tmpbuf,"a+")) == NULL )
        return(-1);
    fprintf( fs, "%s %s\n", ip, domain);
    fclose(fs);

    return(0);
}

int del_ip_map( char *ip, char *domain) {
    FILE *fs;
    FILE *fs1;
    char file1[156];
    char file2[156];
    char tmpbuf[156];
    char tmpbuf1[156];
    char *ip_f;
    char *domain_f;

    if ( ip == NULL || strlen(ip) <= 0 )
        return(-1);
    if ( domain == NULL || strlen(domain) <= 0 )
        return(-1);

    snprintf(file1, 156, "%s/%s", VPOPMAIL_DIR_ETC, IP_ALIAS_MAP_FILE);
    if ( (fs = fopen(file1,"r")) == NULL )
        return(-1);

    snprintf(file2, 156,
             "%s/%s.%d", VPOPMAIL_DIR_ETC, IP_ALIAS_MAP_FILE, getpid());
    if ( (fs1 = fopen(file2,"w")) == NULL ) {
        fclose(fs);
        return(-1);
    }

    while( fgets(tmpbuf, 156, fs) != NULL ) {
        strncpy(tmpbuf1,tmpbuf, 156);

        ip_f = strtok(tmpbuf, IP_ALIAS_TOKENS);
        if ( ip_f == NULL )
            continue;

        domain_f = strtok(NULL, IP_ALIAS_TOKENS);
        if ( domain_f == NULL )
            continue;

        if ( strcmp(ip, ip_f) == 0 && strcmp(domain,domain_f) == 0)
            continue;

        fprintf(fs1, "%s", tmpbuf1);

    }
    fclose(fs);
    fclose(fs1);

    if ( rename( file2, file1) < 0 )
        return(-1);

    return(0);
}

int show_ip_map( int first, char *ip, char *domain) {
    static FILE *fs = NULL;
    char tmpbuf[156];
    char *tmpstr;

    if ( ip == NULL )
        return(-1);
    if ( domain == NULL )
        return(-1);

    if ( first == 1 ) {
        if ( fs != NULL ) {
            fclose(fs);
            fs = NULL;
        }
        snprintf(tmpbuf, 156, "%s/%s", VPOPMAIL_DIR_ETC, IP_ALIAS_MAP_FILE);
        if ( (fs = fopen(tmpbuf,"r")) == NULL )
            return(-1);
    }
    if ( fs == NULL )
        return(-1);

    while (1) {
        if (fgets(tmpbuf, 156, fs) == NULL ) {
            fclose(fs);
            fs = NULL;
            return(0);
        }

        tmpstr = strtok(tmpbuf, IP_ALIAS_TOKENS);
        if ( tmpstr == NULL )
            continue;
        strcpy( ip, tmpstr);

        tmpstr = strtok(NULL, IP_ALIAS_TOKENS);
        if ( tmpstr == NULL )
            continue;
        strcpy( domain, tmpstr);

        return(1);
    }
    return(-1);

}
#endif

/*
   Return an encrypted version of clear_pass
   Supports all encryption methods supplied by the module
*/

int auth_crypt(char *user,char *domain,char *clear_pass,struct vqpasswd *vpw)
{
   int ret = 0;
   char epass[512] = { 0 }, salt[12] = { 0 };

   if ((user == NULL) || (domain == NULL) || (clear_pass == NULL) || (vpw == NULL) || (vpw->pw_passwd == NULL))
	  return -1;

   if (!(strncasecmp(vpw->pw_passwd, "{SMD5}", 6))) {
	  ret = password_scheme_smd5_decode_salt(vpw->pw_passwd, salt, sizeof(salt));
	  if (ret != VA_SUCCESS)
		 return ret;

	  ret = password_scheme_smd5(clear_pass, salt, epass, sizeof(epass));
   }

   else {
	  fprintf(stderr, "auth_crypt: unknown password scheme\n");
	  return -1;
   }

   if (ret != VA_SUCCESS) {
	  fprintf(stderr, "auth_crypt: password scheme failed\n");
	  return -1;
   }

   return strcmp(epass, vpw->pw_passwd);
}

#ifdef VALIAS

/*
   Returns the first deliveryInstruction entry in an existing valias object
*/

char *alias_select(char *alias, char *domain)
{
   return NULL;
}

/*
   Return next deliveryInstruction under a valias object
*/

char *alias_select_next(void)
{
   return NULL;
}

/*
   Add a deliveryInstruction to an existing aliasAddress
   If an aliasAddress does not exist, first add it
*/

int alias_insert(char *alias, char *domain, char *di)
{
   return -1;
}

/*
   Remove an existing deliveryInstruction from an existing
   aliasAddress entry
*/

int alias_remove(char *alias, char *domain, char *di)
{
   return -1;
}


/*
   Remove an existing aliasAddress
*/

int alias_delete(char *alias, char *domain)
{
   return -1;
}

/*
   Remove all valias entries under a domain
*/

int alias_delete_domain(char *domain)
{
   return -1;
}

char *alias_select_all(char *alias, char *domain)
{
   return NULL;
}

char *alias_select_all_next(char *alias)
{
   return NULL;
}

char *alias_select_names(char *alias, char *domain)
{
   return NULL;
}

char *alias_select_names_next(char *alias)
{
   return NULL;
}

/*
   Not used by this module
*/

void alias_select_names_end(void)
{
}

#endif

/*
   Generate a DN for a user or domain
*/

static int create_dn(char *b, int sz, const char *user, const char *domain)
{
   int len = 0;

   if ((b == NULL) || (sz < 1) || (domain == NULL) || (!(*domain)))
	  return;

   if (user)
	  len = snprintf(b, sz, "uid=%s,o=%s,%s", user, domain, basedn);
   else
	  len = snprintf(b, sz, "o=%s,%s", domain, basedn);

   if (len >= sz)
	  return 0;

   return 1;
}

/*
   Initialize a new LDAP operation
*/

static void mod_init(int op)
{
   int i = 0, k = 0;

   if (ldap_mods.attrs) {
	  ldap_mods_free(ldap_mods.attrs, 1);
	  ldap_mods.attrs = NULL;
   }

   ldap_mods.op = op;
   ldap_mods.mods = 0;
}

/*
   Add new field to mod list
*/

static void mod_add(int type, const char *field, const char *value)
{
   void *ptr = NULL;

   /*
	  Allocate
   */

   ptr = NULL;

   if (ldap_mods.mods == 0) {
	  ldap_mods.attrs = malloc(sizeof(LDAPMod *) * 2);
	  if (ldap_mods.attrs == NULL) {
		 fprintf(stderr, "mod_add: malloc failed\n");
		 return;
	  }
   }

   /*
	  Reallocate
   */

   else {
	  ptr = realloc(ldap_mods.attrs, sizeof(LDAPMod *) * (ldap_mods.mods + 2));
	  if (ptr == NULL) {
		 fprintf(stderr, "mod_add: realloc failed\n");
		 return;
	  }

	  ldap_mods.attrs = ptr;
   }

   /*
	  Allocate modification
   */

   ldap_mods.attrs[ldap_mods.mods] = malloc(sizeof(LDAPMod));
   if (ldap_mods.attrs[ldap_mods.mods] == NULL) {
	  fprintf(stderr, "mod_add: malloc failed\n");
	  return;
   }

   memset(ldap_mods.attrs[ldap_mods.mods], 0, sizeof(LDAPMod));

   ldap_mods.attrs[ldap_mods.mods]->mod_type = strdup(field);
   if (ldap_mods.attrs[ldap_mods.mods]->mod_type == NULL) {
	  fprintf(stderr, "mod_add: strdup failed\n");
	  free(ldap_mods.attrs[ldap_mods.mods]);
	  ldap_mods.attrs[ldap_mods.mods] = NULL;
	  return;
   }

   ldap_mods.attrs[ldap_mods.mods]->mod_vals.modv_strvals = (char **)malloc(sizeof(char *) * 2);
   if (ldap_mods.attrs[ldap_mods.mods]->mod_vals.modv_strvals == NULL) {
	  fprintf(stderr, "mod_add: malloc failed\n");
	  free(ldap_mods.attrs[ldap_mods.mods]->mod_type);
	  free(ldap_mods.attrs[ldap_mods.mods]);
	  ldap_mods.attrs[ldap_mods.mods] = NULL;
	  return;
   }

   ldap_mods.attrs[ldap_mods.mods]->mod_vals.modv_strvals[0] = strdup(value);
   if (ldap_mods.attrs[ldap_mods.mods]->mod_vals.modv_strvals[0] == NULL) {
	  fprintf(stderr, "mod_add: strdup failed\n");
	  free(ldap_mods.attrs[ldap_mods.mods]->mod_type);
	  free(ldap_mods.attrs[ldap_mods.mods]->mod_vals.modv_strvals);
	  free(ldap_mods.attrs[ldap_mods.mods]);
	  ldap_mods.attrs[ldap_mods.mods] = NULL;
	  return;
   }

   ldap_mods.attrs[ldap_mods.mods]->mod_vals.modv_strvals[1] = NULL;
   ldap_mods.attrs[ldap_mods.mods]->mod_op = type;

   ldap_mods.mods++;
   ldap_mods.attrs[ldap_mods.mods] = NULL;
}

static int mod_run(const char *dn)
{
   int ret = 0, i = 0;

   if (ldap_mods.op == LDAP_MOD_ADD)
	  ret = ldap_add_ext_s(ldap, dn, ldap_mods.attrs, NULL, NULL);

   else if (ldap_mods.op == LDAP_MOD_REPLACE)
	  ret = ldap_modify_ext_s(ldap, dn, ldap_mods.attrs, NULL, NULL);

   else if (ldap_mods.op == LDAP_MOD_DELETE)
	  ret = ldap_delete_ext_s(ldap, dn, NULL, NULL);

   return ret;
}

/*
   Store result of user result into a vqpasswd structure
*/

static void use_user_result(struct vqpasswd *pw, LDAPMessage *msg)
{
   char **val = NULL;

   /*
	  pw-shell, quota
   */

   val = (char **)ldap_get_values(ldap, msg, "pw-shell");
   if (val) {
	  if (*val)
		 pw->pw_shell = strdup(*val);

	  ldap_value_free(val);
   }

   /*
	  pw-uid
   */

   val = (char **)ldap_get_values(ldap, msg, "pw-uid");
   if (val) {
	  if (*val)
		 pw->pw_uid = atoi(*val);

	  ldap_value_free(val);
   }
   
   /*
	  pw-gid
   */

   val = (char **)ldap_get_values(ldap, msg, "pw-gid");
   if (val) {
	  if (*val)
		 pw->pw_gid = atoi(*val);

	  ldap_value_free(val);
   }

   /*
	  pw-dir
   */

   val = (char **)ldap_get_values(ldap, msg, "pw-dir");
   if (val) {
	  if (*val)
		 pw->pw_dir = strdup(*val);

	  ldap_value_free(val);
   }

   /*
	  cn / pw-gecos
   */

   val = (char **)ldap_get_values(ldap, msg, "cn");
   if (val) {
	  if (*val)
		 pw->pw_gecos = strdup(*val);

	  ldap_value_free(val);
   }

   /*
	  userPassword / pw-passwd
   */

   val = (char **)ldap_get_values(ldap, msg, "userPassword");
   if (val) {
	  if (*val)
		 pw->pw_passwd = strdup(*val);

	  ldap_value_free(val);
   }

   /*
	  pw-clear-passwd
   */

   val = (char **)ldap_get_values(ldap, msg, "pw-clear-passwd");
   if (val) {
	  if (*val)
		 pw->pw_clear_passwd = strdup(*val);

	  ldap_value_free(val);
   }

   /*
	  uid / pw-name
   */

   val = (char **)ldap_get_values(ldap, msg, "uid");
   if (val) {
	  if (*val)
		 pw->pw_name = strdup(*val);

	  ldap_value_free(val);
   }
}

/*
   Deallocate allocated space from use_user_result
*/

static void free_user_result(struct vqpasswd *pw)
{
   if (pw == NULL)
	  return;

   if (pw->pw_shell)
	  free(pw->pw_shell);

   if (pw->pw_dir)
	  free(pw->pw_dir);

   if (pw->pw_gecos)
	  free(pw->pw_gecos);

   if (pw->pw_passwd)
	  free(pw->pw_passwd);

   if (pw->pw_clear_passwd)
	  free(pw->pw_clear_passwd);

   if (pw->pw_name)
	  free(pw->pw_name);

   memset(pw, 0, sizeof(struct vqpasswd));
}

/*
   Parse GECOS to generate the multiple inetOrgPerson entries required
*/

static void parse_gecos(int op, const char *gecos)
{
   int ret = 0, len = 0;
   const char *p = NULL;
   char name[512] = { 0 };

   if ((gecos == NULL) || (!(*gecos)))
	  gecos = "vpopmail user";

   len = strlen(gecos);
   mod_add(op, "cn", gecos);

   /*
	  Parse GECOS for first and last name
   */

   /*
	  Last name or "user"
   */

   for (p = (gecos + len); p > gecos; p--) {
	  if (*p == ' ')
		 break;
   }

   if (p == gecos)
	  mod_add(op, "sn", "user");
   else
	  mod_add(op, "sn", (p + 1));

   /*
	  First name or entire GECOS
   */

   for (p = gecos; *p; p++) {
	  if (*p == ' ')
		 break;
   }

   if (!(*p))
	  mod_add(op, "givenName", gecos);

   else {
	  ret = (p - gecos);
	  if (ret >= sizeof(name))
		 ret = (sizeof(name) - 1);

	  memcpy(name, gecos, ret);
	  *(name + ret) = '\0';

	  mod_add(op, "givenName", name);
   }
}

/*
   Generate SMD5 scheme password
*/

static int password_scheme_smd5(const char *passwd, const char *salt, char *epass, int sz)
{
   int ret = 0;
   MD5_CTX md5ctx;
   unsigned char md5digest[16 + 4] = { 0 }, md5salt[4] = { 0 }, *p = NULL;

   if ((passwd == NULL) || (epass == NULL))
	  return VA_NULL_POINTER;

   if (sz < 45)
	  return VA_INTERNAL_BUFFER_EXCEEDED;

   /*
	  Generate salted MD5 base64 encoded password
   */

   /*
	  Salt
   */

   if (salt == NULL) {
	  md5salt[0] = randltr();
	  md5salt[1] = randltr();
	  md5salt[2] = randltr();
	  md5salt[3] = randltr();
   }

   else
	  memcpy(md5salt, salt, 4);

   /*
	  MD5 hash with salt
   */

   MD5Init(&md5ctx);
   MD5Update(&md5ctx, passwd, strlen(passwd));
   MD5Update(&md5ctx, md5salt, 4);
   MD5Final(md5digest, &md5ctx);

   /*
	  Base64 encoded digest
   */

   memcpy(md5digest + 16, md5salt, 4);
   memset(epass, 0, sz);
   memcpy(epass, "{SMD5}", 6);

   ret = base64_encode(md5digest, sizeof(md5digest), (epass + 6), (sz - 6));
   if (ret != VA_SUCCESS)
	  return VA_CRYPT_FAILED;

   /*
	  Strip newlines from base64 encoding
   */

   for (p = epass; *p; p++) {
	  if ((*p == '\r') || (*p == '\n')) {
		 *p = '\0';
		 break;
	  }
   }

   return VA_SUCCESS;
}

/*
   Retrieve the salt from an SMD5 scheme password
*/

static int password_scheme_smd5_decode_salt(const char *epass, char *salt, int sz)
{
   int ret = 0;
   base64_t b64;
   char buf[80] = { 0 };

   if ((salt == NULL) || (sz < 4))
	  return VA_INTERNAL_BUFFER_EXCEEDED;

   /*
	  Decode the base64 salted MD5 password
   */

   base64_init(&b64);
   ret = base64_decode(&b64, epass, buf, sizeof(buf));
   if (ret != VA_SUCCESS)
	  return ret;

   /*
	  Last four bytes are the salt
   */

   memset(salt, 0, sz);

   salt[0] = buf[19];
   salt[1] = buf[20];
   salt[2] = buf[21];
   salt[3] = buf[22];

   return VA_SUCCESS;
}
