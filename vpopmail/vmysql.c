/*
 * Copyright (C) 1999-2002 Inter7 Internet Technologies, Inc.
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
 
/* TODO

Add error result for "unable to read vpopmail.mysql" and return it

*/ 
 
#include <pwd.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <time.h>
#include <mysql.h>
#include "config.h"
#include "vpopmail.h"
#include "vauth.h"
#include "vlimits.h"
#include "vmysql.h"

static MYSQL mysql_update;
static MYSQL mysql_read_getall;

#ifdef MYSQL_REPLICATION
static MYSQL mysql_read;
#else
#define mysql_read mysql_update
#endif


static int update_open = 0;
static int read_getall_open = 0;

#ifdef MYSQL_REPLICATION
static int read_open = 0;
#else
#define read_open update_open
#endif

static MYSQL_RES *res_update = NULL;
static MYSQL_RES *res_read_getall = NULL;

#ifdef MYSQL_REPLICATION
static MYSQL_RES *res_read = NULL;
#else
#define res_read res_update
#endif

static MYSQL_ROW row;
static MYSQL_ROW row_getall;

#define SQL_BUF_SIZE 2048
static char SqlBufRead[SQL_BUF_SIZE];
static char SqlBufUpdate[SQL_BUF_SIZE];
static char SqlBufCreate[SQL_BUF_SIZE];

#define SMALL_BUFF 200
char IUser[SMALL_BUFF];
char IPass[SMALL_BUFF];
char IGecos[SMALL_BUFF];
char IDir[SMALL_BUFF];
char IShell[SMALL_BUFF];
char IClearPass[SMALL_BUFF];

char EPass[SMALL_BUFF];
char EGecos[SMALL_BUFF];
char EClearPass[SMALL_BUFF];

void vcreate_dir_control(char *domain);
void vcreate_vlog_table();
void vmysql_escape( char *instr, char *outstr );

#ifdef POP_AUTH_OPEN_RELAY
void vcreate_relay_table();
#endif

#ifdef VALIAS
void vcreate_valias_table();
#endif

#ifdef ENABLE_AUTH_LOGGING
void vcreate_lastauth_table();
#endif

/* 
 * get mysql connection info
 */
int load_connection_info() {
    FILE *fp;
    char conn_info[256];
    char config[256];
    int eof;
    static int loaded = 0;
    char *port;
    char delimiters[] = "|\n";
    char *conf_read, *conf_update;

    if (loaded) return 0;
    loaded = 1;

    sprintf(config, "%s/etc/%s", VPOPMAILDIR, "vpopmail.mysql");

    fp = fopen(config, "r");
    if (fp == NULL) {
        fprintf(stderr, "vmysql: can't read settings from %s\n", config);
        return(VA_NO_AUTH_CONNECTION);
    }
    
    /* skip comments and blank lines */
    do {
        eof = (fgets (conn_info, sizeof(conn_info), fp) == NULL);
    } while (!eof && ((*conn_info == '#') || (*conn_info == '\n')));

    if (eof) {
        /* no valid data read, return error */
        fprintf(stderr, "vmysql: no valid settings in %s\n", config);
        return(VA_NO_AUTH_CONNECTION);
    }

    conf_read = strdup(conn_info);
    MYSQL_READ_SERVER = strtok(conf_read, delimiters);
    if (MYSQL_READ_SERVER == NULL) return VA_PARSE_ERROR;
    port = strtok(NULL, delimiters);
    if (port == NULL) return VA_PARSE_ERROR;
    MYSQL_READ_PORT = atoi(port);
    MYSQL_READ_USER = strtok(NULL, delimiters);
    if (MYSQL_READ_USER == NULL) return VA_PARSE_ERROR;
    MYSQL_READ_PASSWD = strtok(NULL, delimiters);
    if (MYSQL_READ_PASSWD == NULL) return VA_PARSE_ERROR;
    MYSQL_READ_DATABASE = strtok(NULL, delimiters);
    if (MYSQL_READ_DATABASE == NULL) return VA_PARSE_ERROR;
    
    /* skip comments and blank lines */
    do {
        eof = (fgets (conn_info, sizeof(conn_info), fp) == NULL);
    } while (!eof && ((*conn_info == '#') || (*conn_info == '\n')));
    
    if (eof) {
        /* re-use read-only settings for update */
        MYSQL_UPDATE_SERVER = MYSQL_READ_SERVER;
        MYSQL_UPDATE_PORT = MYSQL_READ_PORT;
        MYSQL_UPDATE_USER = MYSQL_READ_USER;
        MYSQL_UPDATE_PASSWD = MYSQL_READ_PASSWD;
        MYSQL_UPDATE_DATABASE = MYSQL_READ_DATABASE;
    } else {
        conf_update = strdup(conn_info);
        MYSQL_UPDATE_SERVER = strtok(conf_update, delimiters);
        if (MYSQL_UPDATE_SERVER == NULL) return VA_PARSE_ERROR;
        port = strtok(NULL, delimiters);
        if (port == NULL) return VA_PARSE_ERROR;
        MYSQL_UPDATE_PORT = atoi(port);
        MYSQL_UPDATE_USER = strtok(NULL, delimiters);
        if (MYSQL_UPDATE_USER == NULL) return VA_PARSE_ERROR;
        MYSQL_UPDATE_PASSWD = strtok(NULL, delimiters);
        if (MYSQL_UPDATE_PASSWD == NULL) return VA_PARSE_ERROR;
        MYSQL_UPDATE_DATABASE = strtok(NULL, delimiters);
        if (MYSQL_UPDATE_DATABASE == NULL) return VA_PARSE_ERROR;
    }

/* useful debugging info
    printf ("read settings: server:%s port:%d user:%s pw:%s db:%s\n",
        MYSQL_READ_SERVER, MYSQL_READ_PORT, MYSQL_READ_USER,
        MYSQL_READ_PASSWD, MYSQL_READ_DATABASE);
    printf ("update settings: server:%s port:%d user:%s pw:%s db:%s\n",
        MYSQL_UPDATE_SERVER, MYSQL_UPDATE_PORT, MYSQL_UPDATE_USER,
	MYSQL_UPDATE_PASSWD, MYSQL_UPDATE_DATABASE);    
*/
    return 0;
}

/* 
 * Open a connection to mysql for updates
 */
int vauth_open_update()
{
    unsigned int timeout = 2;

    if ( update_open != 0 ) return(0);
    update_open = 1;

    verrori = load_connection_info();
    if (verrori) return -1;
	
    mysql_init(&mysql_update);
    mysql_options(&mysql_update, MYSQL_OPT_CONNECT_TIMEOUT, (char *)&timeout);

    /* Try to connect to the mysql update server with the specified database. */
    if (!(mysql_real_connect(&mysql_update, MYSQL_UPDATE_SERVER,
            MYSQL_UPDATE_USER, MYSQL_UPDATE_PASSWD,
            MYSQL_UPDATE_DATABASE, MYSQL_UPDATE_PORT, NULL, 0))) {

        /* Could not connect to the update mysql server with the database
         * so try to connect with no database specified
         */
        if (!(mysql_real_connect(&mysql_update, MYSQL_UPDATE_SERVER,
                MYSQL_UPDATE_USER, MYSQL_UPDATE_PASSWD, NULL, MYSQL_UPDATE_PORT,
                NULL, 0))) {

            /* if we can not connect, report a error and return */
            verrori = VA_NO_AUTH_CONNECTION;
            return(VA_NO_AUTH_CONNECTION);
        }

        /* we were able to connect, so create the database */ 
        snprintf( SqlBufUpdate, SQL_BUF_SIZE, 
            "create database %s", MYSQL_UPDATE_DATABASE );
        if (mysql_query(&mysql_update,SqlBufUpdate)) {

            /* we could not create the database
             * so report the error and return 
             */
            fprintf(stderr, "vmysql: sql error[1]: %s\n", mysql_error(&mysql_update));
            return(-1);
        } 
        res_update = mysql_store_result(&mysql_update);
        mysql_free_result(res_update);

        /* set the database */ 
        if (mysql_select_db(&mysql_update, MYSQL_UPDATE_DATABASE)) {
            fprintf(stderr, "could not enter %s database\n", MYSQL_UPDATE_DATABASE);
            return(-1);
        }    
    }
    return(0);
}

#ifdef MYSQL_REPLICATION
/*
 * Open a connection to the database for read-only queries
 */
int vauth_open_read()
{
    /* if we are already connected, just return */
    if ( read_open != 0 ) return(0);
    read_open = 1;
    
    /* connect to mysql and set the database */
    verrori = load_connection_info();
    if (verrori) return -1;
    mysql_init(&mysql_read);
    if (!(mysql_real_connect(&mysql_read, MYSQL_READ_SERVER, 
            MYSQL_READ_USER, MYSQL_READ_PASSWD, MYSQL_READ_DATABASE, 
            MYSQL_READ_PORT, NULL, 0))) {
        /* we could not connect, at least try the update server */
        if (!(mysql_real_connect(&mysql_read, MYSQL_UPDATE_SERVER, 
            MYSQL_UPDATE_USER, MYSQL_UPDATE_PASSWD, MYSQL_UPDATE_DATABASE,
            MYSQL_READ_PORT, NULL, 0))) {
            verrori = VA_NO_AUTH_CONNECTION;
            return( VA_NO_AUTH_CONNECTION );
        }
    }

    /* return success */
    return(0);
}
#else
#define vauth_open_read vauth_open_update
#endif

/*
 * Open a connection to the database for read-only queries
 */
int vauth_open_read_getall()
{

    /* if we are already connected, just return */
    if ( read_getall_open != 0 ) return(0);
    read_getall_open = 1;
    
    /* connect to mysql and set the database */
    verrori = load_connection_info();
    if (verrori) return -1;
    mysql_init(&mysql_read_getall);
    if (!(mysql_real_connect(&mysql_read_getall, MYSQL_READ_SERVER, 
            MYSQL_READ_USER, MYSQL_READ_PASSWD, MYSQL_READ_DATABASE, 
            MYSQL_READ_PORT, NULL, 0))) {
        /* we could not connect, at least try the update server */
        if (!(mysql_real_connect(&mysql_read_getall, MYSQL_UPDATE_SERVER, 
            MYSQL_UPDATE_USER, MYSQL_UPDATE_PASSWD, MYSQL_UPDATE_DATABASE, 
            MYSQL_UPDATE_PORT, NULL, 0))) {
            verrori = VA_NO_AUTH_CONNECTION;
            return(-1);
        }
        return(-1);
    }

    /* return success */
    return(0);
}

int vauth_adddomain( char *domain )
{
 char *tmpstr = NULL;
 int err;
    
    if ( (err=vauth_open_update()) != 0 ) return(err);

    vset_default_domain( domain );
#ifndef MANY_DOMAINS
        tmpstr = vauth_munch_domain( domain );
#else
        tmpstr = MYSQL_DEFAULT_TABLE;
#endif

   snprintf(SqlBufUpdate,SQL_BUF_SIZE, 
       "create table %s ( %s )",tmpstr,TABLE_LAYOUT);

   if (mysql_query(&mysql_update,SqlBufUpdate) ) {
#ifndef MANY_DOMAINS
        return(-1);
#endif
    }
    res_update = mysql_store_result(&mysql_update);
    mysql_free_result(res_update);

    return(0);
}

int vauth_adduser(char *user, char *domain, char *pass, char *gecos, 
    char *dir, int apop )
{
 char *domstr;
 char dom_dir[156];
 uid_t uid; 
 gid_t gid;
 char dirbuf[200];
 char quota[30];
 char Crypted[100];
 int err;
    
    if ( (err=vauth_open_update()) != 0 ) return(err);
    vset_default_domain( domain );

#ifdef HARD_QUOTA
    snprintf( quota, 30, "%s", HARD_QUOTA );
#else
    strncpy( quota, "NOQUOTA", 30 );
#endif

#ifndef MANY_DOMAINS
    domstr = vauth_munch_domain( domain );
#else
    domstr = MYSQL_DEFAULT_TABLE;
#endif
    if ( domain == NULL || domain[0] == 0 ) {
        domstr = MYSQL_LARGE_USERS_TABLE;
    }

    if ( strlen(domain) <= 0 ) {
        if ( strlen(dir) > 0 ) {
            snprintf(dirbuf, SQL_BUF_SIZE, 
                "%s/users/%s/%s", VPOPMAILDIR, dir, user);
        } else {
            snprintf(dirbuf, SQL_BUF_SIZE, "%s/users/%s", VPOPMAILDIR, user);
        }
    } else {
        vget_assign(domain, dom_dir, 156, &uid, &gid );
        if ( strlen(dir) > 0 ) {
            snprintf(dirbuf,SQL_BUF_SIZE, "%s/%s/%s", dom_dir, dir, user);
        } else {
            snprintf(dirbuf, SQL_BUF_SIZE, "%s/%s", dom_dir, user);
        }
    }

    if ( pass[0] != 0 ) {
        mkpasswd3(pass,Crypted, 100);
    } else {
        Crypted[0] = 0;
    }
    vmysql_escape( Crypted, EPass );
    vmysql_escape( gecos, EGecos );
#ifdef CLEAR_PASS
    vmysql_escape( pass, EClearPass);
#endif

    snprintf( SqlBufUpdate, SQL_BUF_SIZE, INSERT, 
      domstr, user, 
#ifdef MANY_DOMAINS
      domain,
#endif
      EPass, apop, EGecos, dirbuf, quota
#ifdef CLEAR_PASS
,EClearPass
#endif
);

    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        printf("vmysql: sql error[2]: %s\n", mysql_error(&mysql_update));
        return(-1);
    } 
    res_update = mysql_store_result(&mysql_update);
    mysql_free_result(res_update);

    return(0);

}

struct vqpasswd *vauth_getpw(char *user, char *domain)
{
 char *domstr;
 static struct vqpasswd vpw;
 static char in_domain[156];
 int err;
 uid_t myuid;
 uid_t uid;
 gid_t gid;
 struct vlimits limits;

    vget_assign(domain,NULL,0,&uid,&gid);

    myuid = geteuid();
    if ( myuid != 0 && myuid != uid ) return(NULL);

    verrori = 0;
    if ( (err=vauth_open_read()) != 0 ) {
        verrori = err;
        return(NULL);
    }

    lowerit(user);
    lowerit(domain);

    snprintf (in_domain, sizeof(in_domain), "%s", domain);

    vset_default_domain( in_domain );

#ifndef MANY_DOMAINS
    domstr = vauth_munch_domain( in_domain );
#else
    domstr = MYSQL_DEFAULT_TABLE; 
#endif

    if ( domstr == NULL || domstr[0] == 0 ) domstr = MYSQL_LARGE_USERS_TABLE;

    snprintf(SqlBufRead, SQL_BUF_SIZE, USER_SELECT, domstr, user
#ifdef MANY_DOMAINS
, in_domain
#endif
);
    if (mysql_query(&mysql_read,SqlBufRead)) {
        printf("vmysql: sql error[3]: %s\n", mysql_error(&mysql_read));
        return(NULL);
    }

    if (!(res_read = mysql_store_result(&mysql_read))) {
        printf("vmysql: store result failed 1\n");
        return(NULL);
    }
    
    if ( mysql_num_rows(res_read) == 0 ) {
        mysql_free_result(res_read);
        return(NULL);
    }

    memset(IUser, 0, sizeof(IUser));
    memset(IPass, 0, sizeof(IPass));
    memset(IGecos, 0, sizeof(IGecos));
    memset(IDir, 0, sizeof(IDir));
    memset(IShell, 0, sizeof(IShell));
    memset(IClearPass, 0, sizeof(IClearPass));

    vpw.pw_name   = IUser;
    vpw.pw_passwd = IPass;
    vpw.pw_gecos  = IGecos;
    vpw.pw_dir    = IDir;
    vpw.pw_shell  = IShell;
    vpw.pw_clear_passwd  = IClearPass;

    if((row = mysql_fetch_row(res_read))) {
        strncpy(vpw.pw_name,row[0],SMALL_BUFF);
        if ( row[1] != 0 )  strncpy(vpw.pw_passwd,row[1],SMALL_BUFF);
        if ( row[2] != 0 ) vpw.pw_uid    = atoi(row[2]);
        if ( row[3] != 0 ) vpw.pw_gid    = atoi(row[3]);
        if ( row[4] != 0 ) strncpy(vpw.pw_gecos,row[4],SMALL_BUFF);
        if ( row[5] != 0 ) strncpy(vpw.pw_dir,row[5],SMALL_BUFF);
        if ( row[6] != 0 ) strncpy(vpw.pw_shell, row[6],SMALL_BUFF);
#ifdef CLEAR_PASS
        if ( row[7] != 0 )  strncpy(vpw.pw_clear_passwd, row[7],SMALL_BUFF);
#endif
    } else {
        mysql_free_result(res_read);
        return(NULL);
    }
    mysql_free_result(res_read);
    /* this is necessary to enforce the qmailadmin-limits
       a gid_mask is created from the qmailadmin-limits, which is then ORed againt the users gid field,
       unless the user has the V_OVERRIDE flag set
    */
    if (vget_limits (in_domain,&limits) == 0) {
        if (! vpw.pw_gid && V_OVERRIDE) {
            vpw.pw_gid |= vlimits_get_gid_mask (&limits);
        }
    }
    return(&vpw);
}

/* del a domain from the auth backend
 * - drop the domain's table, or del all users from users table
 * - delete domain's entries from lastauth table
 * - delete domain's limit's entries
 */
int vauth_deldomain( char *domain )
{
 char *tmpstr;
 int err;
    
    if ( (err=vauth_open_update()) != 0 ) return(err);
    vset_default_domain( domain );

#ifndef MANY_DOMAINS
    /* convert the domain name to the table name (eg convert . to _ ) */
    tmpstr = vauth_munch_domain( domain );
    snprintf( SqlBufUpdate, SQL_BUF_SIZE, "drop table %s", tmpstr);
#else
    tmpstr = MYSQL_DEFAULT_TABLE;
    snprintf( SqlBufUpdate, SQL_BUF_SIZE, "delete from %s where pw_domain = \"%s\"",
        tmpstr, domain );
#endif 

    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        return(-1);
    } 
    res_update = mysql_store_result(&mysql_update);
    mysql_free_result(res_update);

#ifdef VALIAS 
    valias_delete_domain( domain);
#endif

#ifdef ENABLE_AUTH_LOGGING
    snprintf( SqlBufUpdate, SQL_BUF_SIZE, 
        "delete from lastauth where domain = \"%s\"", domain );
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        return(-1);
    } 
    res_update = mysql_store_result(&mysql_update);
    mysql_free_result(res_update);
#endif

    vdel_limits(domain);

    return(0);
}

int vauth_deluser( char *user, char *domain )
{
 char *tmpstr;
 int err = 0;
    
    if ( (err=vauth_open_update()) != 0 ) return(err);
    vset_default_domain( domain );

#ifndef MANY_DOMAINS
    if ( domain == NULL || domain[0] == 0 ) {
        tmpstr = MYSQL_LARGE_USERS_TABLE;
    } else {
        tmpstr = vauth_munch_domain( domain );
    }
#else
    tmpstr = MYSQL_DEFAULT_TABLE;
#endif

    snprintf( SqlBufUpdate,  SQL_BUF_SIZE, DELETE_USER, tmpstr, user
#ifdef MANY_DOMAINS
, domain
#endif
 );
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        err = -1;
    } 
        res_update = mysql_store_result(&mysql_update);
        mysql_free_result(res_update);

#ifdef ENABLE_AUTH_LOGGING
    snprintf( SqlBufUpdate, SQL_BUF_SIZE, 
        "delete from lastauth where user = \"%s\" and domain = \"%s\"", 
        user, domain );
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        err = -1;
    } 
    res_update = mysql_store_result(&mysql_update);
    mysql_free_result(res_update);
#endif
    return(err);
}

int vauth_setquota( char *username, char *domain, char *quota)
{
 char *tmpstr;
 int err;

    if ( strlen(username) > MAX_PW_NAME ) return(VA_USER_NAME_TOO_LONG);
#ifdef USERS_BIG_DIR
    if ( strlen(username) == 1 ) return(VA_ILLEGAL_USERNAME);
#endif
    if ( strlen(domain) > MAX_PW_DOMAIN ) return(VA_DOMAIN_NAME_TOO_LONG);
    if ( strlen(quota) > MAX_PW_QUOTA )    return(VA_QUOTA_TOO_LONG);
    
    if ( (err=vauth_open_update()) != 0 ) return(err);
    vset_default_domain( domain );

#ifndef MANY_DOMAINS
    tmpstr = vauth_munch_domain( domain );
#else
    tmpstr = MYSQL_DEFAULT_TABLE; 
#endif

    snprintf( SqlBufUpdate, SQL_BUF_SIZE, SETQUOTA, tmpstr, quota, username
#ifdef MANY_DOMAINS
, domain
#endif
);

    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        printf("vmysql: sql error[4]: %s\n", mysql_error(&mysql_update));
        return(-1);
    } 
    res_update = mysql_store_result(&mysql_update);
    mysql_free_result(res_update);
    return(0);
}

struct vqpasswd *vauth_getall(char *domain, int first, int sortit)
{
 char *domstr = NULL;
 static struct vqpasswd vpw;
 static int more = 0;
 int err;

    vset_default_domain( domain );

#ifdef MANY_DOMAINS
    domstr = MYSQL_DEFAULT_TABLE; 
#else
    domstr = vauth_munch_domain( domain );
#endif

    if ( first == 1 ) {
        if ( (err=vauth_open_read_getall()) != 0 ) return(NULL);

        snprintf(SqlBufRead,  SQL_BUF_SIZE, GETALL, domstr
#ifdef MANY_DOMAINS
            ,domain
#endif
            );

        if ( sortit == 1 ) {
            strncat( SqlBufRead, " order by pw_name", SQL_BUF_SIZE);
        }

        if (res_read!=NULL) mysql_free_result(res_read_getall);
        res_read = NULL;

        if (mysql_query(&mysql_read_getall,SqlBufRead)) {
            printf("vmysql: sql error[5]: %s\n", mysql_error(&mysql_read_getall));
            return(NULL);
        }

        if (!(res_read_getall=mysql_store_result(&mysql_read_getall))) {
            printf("vsql_getpw: store result failed 2\n");
            return(NULL);
        }
    } else if ( more == 0 ) {
        return(NULL);
    }

    memset(IUser, 0, sizeof(IUser));
    memset(IPass, 0, sizeof(IPass));
    memset(IGecos, 0, sizeof(IGecos));
    memset(IDir, 0, sizeof(IDir));
    memset(IShell, 0, sizeof(IShell));
    memset(IClearPass, 0, sizeof(IClearPass));

    vpw.pw_name   = IUser;
    vpw.pw_passwd = IPass;
    vpw.pw_gecos  = IGecos;
    vpw.pw_dir    = IDir;
    vpw.pw_shell  = IShell;
    vpw.pw_clear_passwd  = IClearPass;
    
    if ((row_getall = mysql_fetch_row(res_read_getall)) != NULL) {
        strncpy(vpw.pw_name,row_getall[0],SMALL_BUFF);
        if (row_getall[1]!=0) strncpy(vpw.pw_passwd,row_getall[1],SMALL_BUFF);
        if (row_getall[2]!=0) vpw.pw_uid = atoi(row_getall[2]);
        if (row_getall[3]!=0) vpw.pw_gid = atoi(row_getall[3]);
        if (row_getall[4]!=0) strncpy(vpw.pw_gecos,row_getall[4],SMALL_BUFF);
        if (row_getall[5]!=0) strncpy(vpw.pw_dir,row_getall[5],SMALL_BUFF);
        if (row_getall[6]!=0) {
            strncpy(vpw.pw_shell, row_getall[6],SMALL_BUFF);
        }
#ifdef CLEAR_PASS
        if (row_getall[7]!=0) {
            strncpy(vpw.pw_clear_passwd, row_getall[7],SMALL_BUFF);
        }
#endif
        more = 1;
        return(&vpw);
    }
    more = 0;
    mysql_free_result(res_read_getall);
    res_read_getall = NULL;
    return(NULL);
}

void vauth_end_getall()
{
    if ( res_read_getall != NULL ) {
        mysql_free_result(res_read_getall);
    }
    res_read_getall = NULL;

}

char *vauth_munch_domain( char *domain )
{
 int i;
 static char tmpbuf[50];

    if ( domain == NULL || domain[0] == 0 ) return(domain);

    for(i=0;domain[i]!=0;++i){
        tmpbuf[i] = domain[i];
        if ( domain[i] == '.' || domain[i] == '-' ) {
            tmpbuf[i] = MYSQL_DOT_CHAR;
        }
    }
    tmpbuf[i] = 0; 
    return(tmpbuf);
}

int vauth_setpw( struct vqpasswd *inpw, char *domain )
{
 char *tmpstr;
 uid_t myuid;
 uid_t uid;
 gid_t gid;
 int err;

    err = vcheck_vqpw(inpw, domain);
    if ( err != 0 ) return(err);

    vget_assign(domain,NULL,0,&uid,&gid);
    myuid = geteuid();
    if ( myuid != 0 && myuid != uid ) {
        return(VA_BAD_UID);
    }

    if ( (err=vauth_open_update()) != 0 ) return(err);
    vset_default_domain( domain );

#ifndef MANY_DOMAINS
    tmpstr = vauth_munch_domain( domain );
#else
    tmpstr = MYSQL_DEFAULT_TABLE; 
#endif

    vmysql_escape( inpw->pw_passwd, EPass );
    vmysql_escape( inpw->pw_gecos, EGecos );
#ifdef CLEAR_PASS
    vmysql_escape( inpw->pw_clear_passwd, EClearPass );
#endif

    snprintf( SqlBufUpdate,SQL_BUF_SIZE,SETPW,
            tmpstr, 
            EPass,
            inpw->pw_uid,
            inpw->pw_gid, 
            EGecos,
            inpw->pw_dir, 
            inpw->pw_shell, 
#ifdef CLEAR_PASS
            EClearPass,
#endif
            inpw->pw_name
#ifdef MANY_DOMAINS
            ,domain
#endif
            );

    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        printf("vmysql: sql error[6]: %s\n", mysql_error(&mysql_update));
        return(-1);
    } 

    res_update = mysql_store_result(&mysql_update);
    mysql_free_result(res_update);

#ifdef SQWEBMAIL_PASS
    vsqwebmail_pass( inpw->pw_dir, inpw->pw_passwd, uid, gid);
#endif

    return(0);
}

#ifdef POP_AUTH_OPEN_RELAY
int vopen_smtp_relay()
{
 char *ipaddr;
 time_t mytime;
 int err;
 int rows;

    mytime = time(NULL);
    ipaddr = getenv("TCPREMOTEIP");
    if ( ipaddr == NULL ) {
        return 0;
    }

    if ( ipaddr != NULL &&  ipaddr[0] == ':') {
        ipaddr +=2;
        while(*ipaddr!=':') ++ipaddr;
        ++ipaddr;
    }

    if ( (err=vauth_open_update()) != 0 ) return 0;

    snprintf( SqlBufUpdate, SQL_BUF_SIZE,
"replace into relay ( ip_addr, timestamp ) values ( \"%s\", %d )",
            ipaddr, (int)mytime);
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        vcreate_relay_table();
        if (mysql_query(&mysql_update,SqlBufUpdate)) {
            printf("vmysql: sql error[7]: %s\n", mysql_error(&mysql_update));
        }
    }
    rows = mysql_affected_rows(&mysql_update);
    res_update = mysql_store_result(&mysql_update);
    mysql_free_result(res_update);

    /* return true if only INSERT (didn't exist) */
    /* would return 2 if replaced, or -1 if error */
    return rows == 1;
}

void vupdate_rules(int fdm)
{
    if (vauth_open_read() != 0) return;

    snprintf(SqlBufRead, SQL_BUF_SIZE, "select ip_addr from relay");
    if (mysql_query(&mysql_read,SqlBufRead)) {
        vcreate_relay_table();
        if (mysql_query(&mysql_read,SqlBufRead)) {
            printf("vmysql: sql error[8]: %s\n", mysql_error(&mysql_read));
            return;
        }
    }
    if (!(res_read = mysql_store_result(&mysql_read))) {
        printf("vsql_getpw: store result failed 3\n");
        return;
    }
    while((row = mysql_fetch_row(res_read))) {
        snprintf(SqlBufRead, SQL_BUF_SIZE, "%s:allow,RELAYCLIENT=\"\",RBLSMTPD=\"\"\n", row[0]);
        write(fdm,SqlBufRead, strlen(SqlBufRead));
    }
    mysql_free_result(res_read);

}

void vclear_open_smtp(time_t clear_minutes, time_t mytime)
{
 time_t delete_time;
 int err;
    
    if ( (err=vauth_open_update()) != 0 ) return; 
    delete_time = mytime - clear_minutes;

    snprintf( SqlBufUpdate, SQL_BUF_SIZE, "delete from relay where timestamp <= %d", 
        (int)delete_time);
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        vcreate_relay_table();
        return;
    }
}

void vcreate_relay_table()
{
    if (vauth_open_update() != 0) return;

    snprintf( SqlBufCreate, SQL_BUF_SIZE, "create table relay ( %s )",RELAY_TABLE_LAYOUT);
    if (mysql_query(&mysql_update,SqlBufCreate)) {
        printf("vmysql: sql error[9]: %s\n", mysql_error(&mysql_update));
        return;
    }
    res_update = mysql_store_result(&mysql_update);
    mysql_free_result(res_update);
    return;
}
#endif

int vmkpasswd( char *domain )
{
    return(0);
}

void vclose()
{
    if (read_open == 1 ) {
        mysql_close(&mysql_read);
        read_open = 0;
    }
    if (read_getall_open == 1 ) {
        mysql_close(&mysql_read_getall);
        read_getall_open = 0;
    }
    if (update_open == 1 ) {
        mysql_close(&mysql_update);
        update_open = 0;
    }
}

#ifdef IP_ALIAS_DOMAINS
void vcreate_ip_map_table()
{
    if ( vauth_open_update() != 0 ) return;

    snprintf(SqlBufCreate, SQL_BUF_SIZE, "create table ip_alias_map ( %s )", 
      IP_ALIAS_TABLE_LAYOUT);
    if (mysql_query(&mysql_update,SqlBufCreate)) {
        printf("vmysql: sql error[a]: %s\n", mysql_error(&mysql_update));
        return;
    }
    res_update = mysql_store_result(&mysql_update);
    mysql_free_result(res_update);
    return;
}

int vget_ip_map( char *ip, char *domain, int domain_size)
{
 int ret = -1;

    if ( ip == NULL || strlen(ip) <= 0 ) return(-1);
    if ( domain == NULL ) return(-2);
    if ( vauth_open_read() != 0 ) return(-3);

    snprintf(SqlBufRead, SQL_BUF_SIZE, "select domain from ip_alias_map where ip_addr = \"%s\"",
        ip);
    if (mysql_query(&mysql_read,SqlBufRead)) {
        return(-1);
    }

    if (!(res_read = mysql_store_result(&mysql_read))) {
        printf("vget_ip_map: store result failed 4\n");
        return(-4);
    }
    while((row = mysql_fetch_row(res_read))) {
        ret = 0;
        strncpy(domain, row[0], domain_size);
    }
    mysql_free_result(res_read);
    res_update = mysql_store_result(&mysql_read);
    return(ret);
}

int vadd_ip_map( char *ip, char *domain) 
{
    if ( ip == NULL || strlen(ip) <= 0 ) return(-1);
    if ( domain == NULL || strlen(domain) <= 0 ) return(-1);
    if ( vauth_open_update() != 0 ) return(-1);

    snprintf(SqlBufUpdate,SQL_BUF_SIZE,  
      "replace into ip_alias_map ( ip_addr, domain ) values ( \"%s\", \"%s\" )",
      ip, domain);
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        vcreate_ip_map_table();
        if (mysql_query(&mysql_update,SqlBufUpdate)) {
            return(-1);
        }
    }
    res_update = mysql_store_result(&mysql_update);
    mysql_free_result(res_update);
    return(0);
}

int vdel_ip_map( char *ip, char *domain) 
{
    if ( ip == NULL || strlen(ip) <= 0 ) return(-1);
    if ( domain == NULL || strlen(domain) <= 0 ) return(-1);
    if ( vauth_open_update() != 0 ) return(-1);

    snprintf( SqlBufUpdate,SQL_BUF_SIZE,  
        "delete from ip_alias_map where ip_addr = \"%s\" and domain = \"%s\"",
            ip, domain);
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        return(0);
    } 
    res_update = mysql_store_result(&mysql_update);
    mysql_free_result(res_update);
    return(0);
}

int vshow_ip_map( int first, char *ip, char *domain )
{
 static int more = 0;

    if ( ip == NULL ) return(-1);
    if ( domain == NULL ) return(-1);
    if ( vauth_open_read() != 0 ) return(-1);

    if ( first == 1 ) {

        snprintf(SqlBufRead,SQL_BUF_SIZE, 
            "select ip_addr, domain from ip_alias_map"); 

        if (res_read!=NULL) mysql_free_result(res_read);
        res_read = NULL;

        if (mysql_query(&mysql_read,SqlBufRead)) {
            vcreate_ip_map_table();
            if (mysql_query(&mysql_read,SqlBufRead)) {
                return(0);
            }
        }

        if (!(res_read = mysql_store_result(&mysql_read))) {
            printf("vsql_getpw: store result failed 5\n");
            return(0);
        }
    } else if ( more == 0 ) {
        return(0);
    }

    if ((row = mysql_fetch_row(res_read)) != NULL) {
        strncpy(ip, row[0], 18); 
        strncpy(domain, row[1], 156); 
        more = 1;
        return(1);
    }
    more = 0;
    mysql_free_result(res_read);
    res_read = NULL;
    return(0);
}
#endif

int vread_dir_control(vdir_type *vdir, char *domain, uid_t uid, gid_t gid)
{
 int found = 0;

    if ( vauth_open_read() != 0 ) return(-1);
    snprintf(SqlBufRead, SQL_BUF_SIZE, 
        "select %s from dir_control where domain = \"%s\"", 
        DIR_CONTROL_SELECT, domain );
    if (mysql_query(&mysql_read,SqlBufRead)) {
        vcreate_dir_control(domain);
        snprintf(SqlBufRead, SQL_BUF_SIZE, 
            "select %s from dir_control where domain = \"%s\"", 
           DIR_CONTROL_SELECT, domain );
        if (mysql_query(&mysql_read,SqlBufRead)) {
            return(-1);
        }
    }
    if (!(res_read = mysql_store_result(&mysql_read))) {
        printf("vread_dir_control: store result failed 6\n");
        return(0);
    }

    if ((row = mysql_fetch_row(res_read)) != NULL) {
        found = 1;
        vdir->cur_users = atol(row[0]);
        vdir->level_cur = atoi(row[1]);
        vdir->level_max = atoi(row[2]);

        vdir->level_start[0] = atoi(row[3]);
        vdir->level_start[1] = atoi(row[4]);
        vdir->level_start[2] = atoi(row[5]);

        vdir->level_end[0] = atoi(row[6]);
        vdir->level_end[1] = atoi(row[7]);
        vdir->level_end[2] = atoi(row[8]);

        vdir->level_mod[0] = atoi(row[9]);
        vdir->level_mod[1] = atoi(row[10]);
        vdir->level_mod[2] = atoi(row[11]);

        vdir->level_index[0] = atoi(row[12]);
        vdir->level_index[1] = atoi(row[13]);
        vdir->level_index[2] = atoi(row[14]);

        strncpy(vdir->the_dir, row[15], MAX_DIR_NAME);
    }
    mysql_free_result(res_read);

    if ( found == 0 ) {
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
    }
    return(0);
}

int vwrite_dir_control(vdir_type *vdir, char *domain, uid_t uid, gid_t gid)
{
    if ( vauth_open_update() != 0 ) return(-1);

    snprintf(SqlBufUpdate, SQL_BUF_SIZE, "replace into dir_control ( \
domain, cur_users, \
level_cur, level_max, \
level_start0, level_start1, level_start2, \
level_end0, level_end1, level_end2, \
level_mod0, level_mod1, level_mod2, \
level_index0, level_index1, level_index2, the_dir ) values ( \
\"%s\", %lu, %d, %d, \
%d, %d, %d, \
%d, %d, %d, \
%d, %d, %d, \
%d, %d, %d, \
\"%s\")\n",
    domain, vdir->cur_users, vdir->level_cur, vdir->level_max,
    vdir->level_start[0], vdir->level_start[1], vdir->level_start[2],
    vdir->level_end[0], vdir->level_end[1], vdir->level_end[2],
    vdir->level_mod[0], vdir->level_mod[1], vdir->level_mod[2],
    vdir->level_index[0], vdir->level_index[1], vdir->level_index[2],
    vdir->the_dir);

    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        vcreate_dir_control(domain);
        if (mysql_query(&mysql_update,SqlBufUpdate)) {
            printf("vmysql: sql error[b]: %s\n", mysql_error(&mysql_update));
            return(-1);
        }
    }
    res_update = mysql_store_result(&mysql_update);
    mysql_free_result(res_update);

    return(0);
}

void vcreate_dir_control(char *domain)
{
    if ( vauth_open_update() != 0 ) return;

    snprintf(SqlBufCreate, SQL_BUF_SIZE, "create table dir_control ( %s )", 
        DIR_CONTROL_TABLE_LAYOUT);

    if (mysql_query(&mysql_update,SqlBufCreate)) {
        printf("vmysql: sql error[c]: %s\n", mysql_error(&mysql_update));
        return;
    }
    res_update = mysql_store_result(&mysql_update);
    mysql_free_result(res_update);

    snprintf(SqlBufUpdate, SQL_BUF_SIZE, "replace into dir_control ( \
domain, cur_users, \
level_cur, level_max, \
level_start0, level_start1, level_start2, \
level_end0, level_end1, level_end2, \
level_mod0, level_mod1, level_mod2, \
level_index0, level_index1, level_index2, the_dir ) values ( \
\"%s\", 0, \
0, %d, \
0, 0, 0, \
%d, %d, %d, \
0, 2, 4, \
0, 0, 0, \
\"\")\n",
    domain, MAX_DIR_LEVELS, MAX_DIR_LIST-1, MAX_DIR_LIST-1, MAX_DIR_LIST-1);

    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        printf("vmysql: sql error[d]: %s\n", mysql_error(&mysql_update));
        return;
    }
    res_update = mysql_store_result(&mysql_update);
    mysql_free_result(res_update);
}

int vdel_dir_control(char *domain)
{
 int err;

    if ( (err=vauth_open_update()) != 0 ) return(err);

    snprintf(SqlBufUpdate, SQL_BUF_SIZE, 
        "delete from dir_control where domain = \"%s\"", 
        domain); 
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        vcreate_dir_control(domain);
            if (mysql_query(&mysql_update,SqlBufUpdate)) {
                printf("vmysql: sql error[e]: %s\n", mysql_error(&mysql_update));
                return(-1);
        }
    }
    res_update = mysql_store_result(&mysql_update);
    mysql_free_result(res_update);

    return(0);
}

#ifdef ENABLE_AUTH_LOGGING
int vset_lastauth(char *user, char *domain, char *remoteip )
{
 int err;

    if ( (err=vauth_open_update()) != 0 ) return(err);

    snprintf( SqlBufUpdate, SQL_BUF_SIZE,
"replace into lastauth set user=\"%s\", domain=\"%s\", \
remote_ip=\"%s\", timestamp=%lu", user, domain, remoteip, time(NULL)); 
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        vcreate_lastauth_table();
        if (mysql_query(&mysql_update,SqlBufUpdate)) {
            printf("vmysql: sql error[f]: %s\n", mysql_error(&mysql_update));
        }
    }
    res_update = mysql_store_result(&mysql_update);
    mysql_free_result(res_update);
    return(0);
}

time_t vget_lastauth(struct vqpasswd *pw, char *domain)
{
 int err;
 time_t mytime;

    if ( (err=vauth_open_read()) != 0 ) return(err);

    snprintf( SqlBufRead,  SQL_BUF_SIZE,
    "select timestamp from lastauth where user=\"%s\" and domain=\"%s\"", 
        pw->pw_name, domain);
    if (mysql_query(&mysql_read,SqlBufRead)) {
        vcreate_lastauth_table();
        if (mysql_query(&mysql_read,SqlBufRead)) {
            printf("vmysql: sql error[g]: %s\n", mysql_error(&mysql_read));
            return(0);
        }
    }
    res_read = mysql_store_result(&mysql_read);
    mytime = 0;
    while((row = mysql_fetch_row(res_read))) {
        mytime = atol(row[0]);
    }
    mysql_free_result(res_read);
    return(mytime);
}

char *vget_lastauthip(struct vqpasswd *pw, char *domain)
{
 static char tmpbuf[100];

    if ( vauth_open_read() != 0 ) return(NULL);

    snprintf( SqlBufRead,  SQL_BUF_SIZE,
    "select remote_ip from lastauth where user=\"%s\" and domain=\"%s\"", 
        pw->pw_name, domain);
    if (mysql_query(&mysql_read,SqlBufRead)) {
        vcreate_lastauth_table();
        if (mysql_query(&mysql_read,SqlBufRead)) {
            printf("vmysql: sql error[h]: %s\n", mysql_error(&mysql_read));
            return(NULL);
        }
    }
    res_read = mysql_store_result(&mysql_read);
    while((row = mysql_fetch_row(res_read))) {
        strncpy(tmpbuf,row[0],100);
    }
    mysql_free_result(res_read);
    return(tmpbuf);
}

void vcreate_lastauth_table()
{

    if ( vauth_open_update() != 0 ) return;

    snprintf( SqlBufCreate, SQL_BUF_SIZE, "create table lastauth ( %s )", 
        LASTAUTH_TABLE_LAYOUT);
    if (mysql_query(&mysql_update,SqlBufCreate)) {
        printf("vmysql: sql error[i]: %s\n", mysql_error(&mysql_update));
        return;
    }
    res_update = mysql_store_result(&mysql_update);
    mysql_free_result(res_update);
    return;
}
#endif

#ifdef VALIAS
char *valias_select( char *alias, char *domain )
{
 int err;

    /* if we can not connect, set the verrori value */
    if ( (err=vauth_open_read()) != 0 ) {
      return(NULL);
    }

    snprintf( SqlBufRead, SQL_BUF_SIZE, "select valias_line from valias \
where alias = \"%s\" and domain = \"%s\"", alias, domain );

    if (mysql_query(&mysql_read,SqlBufRead)) {
        vcreate_valias_table();
        if (mysql_query(&mysql_read,SqlBufRead)) {
            printf("vmysql: sql error[j]: %s\n", mysql_error(&mysql_read));
            return(NULL);
        }
    }
    res_read = mysql_store_result(&mysql_read);
    return(valias_select_next());
}

char *valias_select_next()
{
    if((row = mysql_fetch_row(res_read))) {
        return(row[0]);
    }
    mysql_free_result(res_read);
    return(NULL);
}

int valias_insert( char *alias, char *domain, char *alias_line)
{
 int err;

    if ( (err=vauth_open_update()) != 0 ) return(err);
    while(*alias_line==' ' && *alias_line!=0) ++alias_line;

    snprintf( SqlBufUpdate, SQL_BUF_SIZE, "insert into valias \
( alias, domain, valias_line ) values ( \"%s\", \"%s\", \"%s\")",
        alias, domain, alias_line );

    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        vcreate_valias_table();
        if (mysql_query(&mysql_update,SqlBufUpdate)) {
            printf("vmysql: sql error[k]: %s\n", mysql_error(&mysql_update));
            return(-1);
        }
    }
    res_update = mysql_store_result(&mysql_update);
    mysql_free_result(res_update);
    return(0);
}

int valias_delete( char *alias, char *domain)
{
 int err;

    if ( (err=vauth_open_update()) != 0 ) return(err);

    snprintf( SqlBufUpdate, SQL_BUF_SIZE, 
        "delete from valias where alias = \"%s\" \
and domain = \"%s\"", alias, domain );

    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        vcreate_valias_table();
        if (mysql_query(&mysql_update,SqlBufUpdate)) {
            printf("vmysql: sql error: %s\n", mysql_error(&mysql_update));
            return(-1);
        }
    }
    res_update = mysql_store_result(&mysql_update);
    mysql_free_result(res_update);
    return(0);
}

int valias_delete_domain( char *domain)
{
 int err;

    if ( (err=vauth_open_update()) != 0 ) return(err);

    snprintf( SqlBufUpdate, SQL_BUF_SIZE, 
        "delete from valias where domain = \"%s\"", 
        domain );

    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        vcreate_valias_table();
        if (mysql_query(&mysql_update,SqlBufUpdate)) {
            printf("vmysql: sql error[l]: %s\n", mysql_error(&mysql_update));
            return(-1);
        }
    }
    res_update = mysql_store_result(&mysql_update);
    mysql_free_result(res_update);
    return(0);
}

void vcreate_valias_table()
{
    if ( vauth_open_update() != 0 ) return;

    snprintf( SqlBufCreate, SQL_BUF_SIZE, "create table valias ( %s )", 
        VALIAS_TABLE_LAYOUT );
    if (mysql_query(&mysql_update,SqlBufCreate)) {
        printf("vmysql: sql error[n]: %s\n", mysql_error(&mysql_update));
        return;
    }
    res_update = mysql_store_result(&mysql_update);
    mysql_free_result(res_update);
    return;
}

char *valias_select_all( char *alias, char *domain )
{
 int err;

    if ( (err=vauth_open_read()) != 0 ) return(NULL);

    snprintf( SqlBufRead, SQL_BUF_SIZE, 
        "select alias, valias_line from valias where domain = \"%s\"", domain );

    if (mysql_query(&mysql_read,SqlBufRead)) {
        vcreate_valias_table();
        if (mysql_query(&mysql_read,SqlBufRead)) {
            printf("vmysql: sql error[o]: %s\n", mysql_error(&mysql_read));
            return(NULL);
        }
    }
    res_read = mysql_store_result(&mysql_read);
    return(valias_select_all_next(alias));
}

char *valias_select_all_next(char *alias)
{
    if((row = mysql_fetch_row(res_read))) {
        strcpy( alias, (row[0]));
        return(row[1]);
    }
    mysql_free_result(res_read);
    return(NULL);
}
#endif

#ifdef ENABLE_MYSQL_LOGGING
int logmysql(int verror, char *TheUser, char *TheDomain, char *ThePass, 
  char *TheName, char *IpAddr, char *LogLine) 
{
 int err;
 time_t mytime;
 

    mytime = time(NULL);
    if ( (err=vauth_open_update()) != 0 ) return(err);

    snprintf( SqlBufUpdate, SQL_BUF_SIZE,
        "INSERT INTO vlog set user=\"%s\", passwd=\"%s\", \
        domain=\"%s\", logon=\"%s\", remoteip=\"%s\", message=\"%s\", \
        error=%i, timestamp=%d", TheUser, ThePass, TheDomain,
        TheName, IpAddr, LogLine, verror, (int)mytime);

    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        vcreate_vlog_table();
        if (mysql_query(&mysql_update,SqlBufUpdate)) {
                fprintf(stderr,
                  "error inserting into vlog table\n");
        }
    }
    res_update = mysql_store_result(&mysql_update);
    mysql_free_result(res_update);
    return(0);
}


void vcreate_vlog_table()
{

    if ( vauth_open_update() != 0 ) return;

    snprintf( SqlBufCreate, SQL_BUF_SIZE, "CREATE TABLE vlog ( %s )",
        VLOG_TABLE_LAYOUT);
    if (mysql_query(&mysql_update,SqlBufCreate)) {
        fprintf(stderr, "could not create vlog table %s\n", SqlBufCreate);
        return;
    }
    res_update = mysql_store_result(&mysql_update);
    mysql_free_result(res_update);
    return;
}
#endif

void vmysql_escape( char *instr, char *outstr )
{

  /* escape out " characters */
  while( *instr != 0 ) {
    if ( *instr == '"' ) *outstr++ = '\\';
    *outstr++ = *instr++;
  }

  /* make sure the terminating NULL char is included */
  *outstr++ = *instr++;
}

#ifdef ENABLE_MYSQL_LIMITS
void vcreate_limits_table()
{
    if (vauth_open_update() != 0)
        return;

    snprintf( SqlBufCreate, SQL_BUF_SIZE, "CREATE TABLE limits ( %s )",
        LIMITS_TABLE_LAYOUT);
    if (mysql_query(&mysql_update,SqlBufCreate)) {
        fprintf(stderr, "could not create limits table %s\n", SqlBufCreate);
        return;
    }
    res_update = mysql_store_result(&mysql_update);
    mysql_free_result(res_update);
}

int vget_limits(const char *domain, struct vlimits *limits)
{
    vdefault_limits (limits);

    if (vauth_open_read() != 0)
         return(-1);

    snprintf(SqlBufRead, SQL_BUF_SIZE, "SELECT maxpopaccounts, maxaliases, "
        "maxforwards, maxautoresponders, maxmailinglists, diskquota, "
        "maxmsgcount, defaultquota, defaultmaxmsgcount, "
        "disable_pop, disable_imap, disable_dialup, "
        "disable_passwordchanging, disable_webmail, disable_relay, "
        "disable_smtp, perm_account, perm_alias, perm_forward, "
        "perm_autoresponder, perm_maillist, perm_quota, perm_defaultquota \n"
        "FROM limits \n"
        "WHERE domain = '%s'", domain);


    if (mysql_query(&mysql_read,SqlBufRead)) {
        vcreate_limits_table();
        if (mysql_query(&mysql_read,SqlBufRead)) {
            fprintf(stderr, "vmysql: sql error[j]: %s\n", mysql_error(&mysql_read));
            return(-1);
        }
    }
    if (!(res_read = mysql_store_result(&mysql_read))) {
        fprintf(stderr, "vmysql: store result failed\n");
        return -1;
    }

    if (mysql_num_rows(res_read) == 0) {
        /* this should not be a fatal error: upgrading gets extremly annoying elsewise. */
        /*fprintf(stderr, "vmysql: can't find limits for domain '%s', using defaults.\n", domain);
        return -1;*/
        /* instead, we return the result of our attempt of reading the limits from the default limits file */
        return vlimits_read_limits_file (VLIMITS_DEFAULT_FILE, limits);

    } else if ((row = mysql_fetch_row(res_read)) != NULL) {
        int perm = atol(row[20]);

        limits->maxpopaccounts = atoi(row[0]);
        limits->maxaliases = atoi(row[1]);
        limits->maxforwards = atoi(row[2]);
        limits->maxautoresponders = atoi(row[3]);
        limits->maxmailinglists = atoi(row[4]);
        limits->diskquota = atoi(row[5]);
        limits->maxmsgcount = atoi(row[6]);
        limits->defaultquota = atoi(row[7]);
        limits->defaultmaxmsgcount = atoi(row[8]);
        limits->disable_pop = atoi(row[9]);
        limits->disable_imap = atoi(row[10]);
        limits->disable_dialup = atoi(row[11]);
        limits->disable_passwordchanging = atoi(row[12]);
        limits->disable_webmail = atoi(row[13]);
        limits->disable_relay = atoi(row[14]);
        limits->disable_smtp = atoi(row[15]);
        limits->perm_account = atoi(row[16]);
        limits->perm_alias = atoi(row[17]);
        limits->perm_forward = atoi(row[18]);
        limits->perm_autoresponder = atoi(row[19]);
        limits->perm_maillist = perm & VLIMIT_DISABLE_ALL;
        perm >>= VLIMIT_DISABLE_BITS;
        limits->perm_maillist_users = perm & VLIMIT_DISABLE_ALL;
        perm >>= VLIMIT_DISABLE_BITS;
        limits->perm_maillist_moderators = perm & VLIMIT_DISABLE_ALL;
        limits->perm_quota = atoi(row[21]);
        limits->perm_defaultquota = atoi(row[22]);
    }
    mysql_free_result(res_read);

    return 0;
}

int vset_limits(const char *domain, const struct vlimits *limits)
{
    if (vauth_open_update() != 0)
        return(-1);

    snprintf(SqlBufUpdate, SQL_BUF_SIZE, "REPLACE INTO limits ("
        "domain, maxpopaccounts, maxaliases, "
        "maxforwards, maxautoresponders, maxmailinglists, "
        "diskquota, maxmsgcount, defaultquota, defaultmaxmsgcount, "
        "disable_pop, disable_imap, disable_dialup, "
        "disable_passwordchanging, disable_webmail, disable_relay, "
        "disable_smtp, perm_account, perm_alias, perm_forward, "
        "perm_autoresponder, perm_maillist, perm_quota, perm_defaultquota) \n"
        "VALUES \n"
        "('%s', %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d)",
        domain,
        limits->maxpopaccounts,
        limits->maxaliases,
        limits->maxforwards,
        limits->maxautoresponders,
        limits->maxmailinglists,
        limits->diskquota,
        limits->maxmsgcount,
        limits->defaultquota,
        limits->defaultmaxmsgcount,
        limits->disable_pop,
        limits->disable_imap,
        limits->disable_dialup,
        limits->disable_passwordchanging,
        limits->disable_webmail,
        limits->disable_relay,
        limits->disable_smtp,
        limits->perm_account,
        limits->perm_alias,
        limits->perm_forward,
        limits->perm_autoresponder,
        (limits->perm_maillist |
         (limits->perm_maillist_users << VLIMIT_DISABLE_BITS) |
         (limits->perm_maillist_moderators << (VLIMIT_DISABLE_BITS * 2))),
        limits->perm_quota,
        limits->perm_defaultquota);

    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        vcreate_limits_table();
        if (mysql_query(&mysql_update,SqlBufUpdate)) {
            fprintf(stderr, "vmysql: sql error[j]: %s\n", mysql_error(&mysql_update));
            return(-1);
        }
    }
    if (!(res_update = mysql_store_result(&mysql_update))) {
        fprintf(stderr, "vmysql: store result failed\n");
        return -1;
    }
    mysql_free_result(res_update);

    return 0;
}

int vdel_limits(const char *domain)
{
    snprintf(SqlBufUpdate, SQL_BUF_SIZE, "DELETE FROM limits WHERE domain = \"%s\"", domain);

    if (mysql_query(&mysql_update,SqlBufUpdate))
        return(-1);
    res_update = mysql_store_result(&mysql_update);
    mysql_free_result(res_update);
    return 0;
}

#endif

int vauth_crypt(char *user,char *domain,char *clear_pass,struct vqpasswd *vpw)
{
  if ( vpw == NULL ) return(-1);

  return(strcmp(crypt(clear_pass,vpw->pw_passwd),vpw->pw_passwd));
}
