/*
 * $Id: vmysql.c,v 1.23 2004-11-23 15:47:03 tomcollins Exp $
 * Copyright (C) 1999-2004 Inter7 Internet Technologies, Inc.
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

#define SMALL_BUFF 200
char IUser[SMALL_BUFF];
char IPass[SMALL_BUFF];
char IGecos[SMALL_BUFF];
char IDir[SMALL_BUFF];
char IShell[SMALL_BUFF];
char IClearPass[SMALL_BUFF];

char sqlerr[MAX_BUFF] = "";
char *last_query = NULL;
int  showerrors=1;

void vcreate_dir_control(char *domain);
void vcreate_vlog_table();

#ifdef POP_AUTH_OPEN_RELAY
void vcreate_relay_table();
#endif

#ifdef VALIAS
void vcreate_valias_table();
#endif

#ifdef ENABLE_AUTH_LOGGING
void vcreate_lastauth_table();
#endif

/**************************************************************************
 *
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

#ifdef SHOW_TRACE
    fprintf( stderr, "load_connection_info() loaded: %i\n", loaded );
#endif

    if (loaded) return 0;
    loaded = 1;

    sprintf(config, "%s/etc/%s", VPOPMAILDIR, "vpopmail.mysql");

    fp = fopen(config, "r");
    if (fp == NULL) {
        snprintf(sqlerr, MAX_BUFF,
                 "   Can't read settings from %s\n", 
                 config);
        verrori = VA_NO_AUTH_CONNECTION;
        if( showerrors ) { 
            vsqlerror( stderr, "open connection file" );
        }

        return( verrori );
    }
    
    /* skip comments and blank lines */
    do {
        eof = (fgets (conn_info, sizeof(conn_info), fp) == NULL);
    } while (!eof && ((*conn_info == '#') || (*conn_info == '\n')));

    if (eof) {
        /* no valid data read, return error */
        snprintf(sqlerr, MAX_BUFF,
                 "   No valid settings in %s\n", config);
        verrori = VA_NO_AUTH_CONNECTION;
        if( showerrors ) {
            vsqlerror( stderr, "Reading SQL settings file" );
        }
        return( verrori );
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

#ifdef DUMP_DATA
/* useful debugging info  */
    fprintf(stderr, "   connection settings:\n" );
    fprintf(stderr, "      read:   server:%s port:%d user:%s pw:%s db:%s\n",
        MYSQL_READ_SERVER, MYSQL_READ_PORT, MYSQL_READ_USER,
        MYSQL_READ_PASSWD, MYSQL_READ_DATABASE);
    fprintf(stderr, "      update: server:%s port:%d user:%s pw:%s db:%s\n",
        MYSQL_UPDATE_SERVER, MYSQL_UPDATE_PORT, MYSQL_UPDATE_USER,
	MYSQL_UPDATE_PASSWD, MYSQL_UPDATE_DATABASE);    
#endif

    return 0;
}

/************************************************************************
 *
 * Open a connection to mysql for updates
 */

int vauth_open_update()
{
    unsigned int timeout = 2;

    if ( update_open != 0 ) return(0);
    update_open = 1;

#ifdef SHOW_TRACE
    fprintf( stderr, "open_update()\n");
#endif

    if( load_connection_info())  return( verrori );
	
    mysql_init(&mysql_update);

    mysql_options(&mysql_update, MYSQL_OPT_CONNECT_TIMEOUT, (char *)&timeout);

    /* Try to connect to the mysql update server */
    if (!(mysql_real_connect(&mysql_update, MYSQL_UPDATE_SERVER,
                             MYSQL_UPDATE_USER, MYSQL_UPDATE_PASSWD,
                             NULL, MYSQL_UPDATE_PORT, NULL, 0))) {

        snprintf(sqlerr, MAX_BUFF,
                 "   Can not connect to update database - %s\n", 
                 mysql_error( &mysql_update ));
#ifdef SHOW_TRACE
        snprintf( SqlBufUpdate, SQL_BUF_SIZE, 
                 "   mysql_real_connect - Server %s  User %s  "
                 "Password: %s Base: NULL Port: %s ?:NULL\n", 
                 MYSQL_UPDATE_SERVER, MYSQL_UPDATE_USER, 
                 MYSQL_UPDATE_PASSWD, MYSQL_UPDATE_PORT);
#else
        snprintf( SqlBufUpdate, SQL_BUF_SIZE, 
                 "   mysql_real_connect( - Server %s  User %s  "
                 "Password: *** Base: NULL Port: %i ?:NULL )\n", 
                 MYSQL_UPDATE_SERVER, MYSQL_UPDATE_USER, 
                 MYSQL_UPDATE_PORT);
        last_query = SqlBufUpdate;
#endif
        verrori = VA_NO_AUTH_CONNECTION;
    
#ifdef SHOW_TRACE
        last_query = SqlBufUpdate;
        fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
        if( showerrors ) {
            vsqlerror( stderr, "Connecting to the database server" );
        }
        return( verrori );
    }

#ifdef SHOW_TRACE
    fprintf( stderr, "   Now try to select database\n");
#endif

    if (mysql_select_db(&mysql_update, MYSQL_UPDATE_DATABASE)) {

#ifdef SHOW_TRACE
        fprintf( stderr, "   Now try to create database\n");
#endif

        snprintf( SqlBufUpdate, SQL_BUF_SIZE, 
                  "create database %s", MYSQL_UPDATE_DATABASE );
#ifdef SHOW_QUERY
        fprintf( stderr, "open_update query\n%s\n", SqlBufUpdate );
#endif

        if (mysql_query(&mysql_update,SqlBufUpdate)) {
            snprintf(sqlerr, MAX_BUFF, 
                     "   Unable to create database - %s\n", 
                     mysql_error( &mysql_update ));
            last_query = SqlBufUpdate;
            verrori = VA_CANNOT_CREATE_DATABASE;

#ifdef SHOW_TRACE
            fprintf(stderr, "   %s\n   %s\n", sqlerr, last_query );
#endif
            if( showerrors ) {
                vsqlerror( stderr, "Creating database" );
            }
            return( verrori );
        }

#ifdef SHOW_TRACE
        fprintf( stderr, "   Now try to select database we just created\n");
#endif

        fprintf( stderr, "   before select\n");
        /* set the database */ 
        if (mysql_select_db(&mysql_update, MYSQL_UPDATE_DATABASE)) {
            snprintf(sqlerr, MAX_BUFF, 
                     "   Unable to select new database - %s\n", 
                     mysql_error( &mysql_update ));
            snprintf( SqlBufUpdate, SQL_BUF_SIZE, 
                      "   mysql_select( database: %s )", 
                      MYSQL_UPDATE_DATABASE );
            last_query = SqlBufUpdate;
            verrori = VA_CANNOT_OPEN_DATABASE;

#ifdef SHOW_TRACE
            fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
            if( showerrors ) {
                vsqlerror( stderr, "Selectin database" );
            }
            return( verrori );
        }    
    }
    return(0);
}

/************************************************************************
 *
 * Open a connection to the database for read-only queries
 */

#ifdef MYSQL_REPLICATION

int vauth_open_read()
{
    /* if we are already connected, just return */
    if ( read_open != 0 ) return(0);
    read_open = 1;
    
//#ifdef SHOW_TRACE
    fprintf( stderr, "open_read()\n" );
//#endif

    /* connect to mysql and set the database */
    if( load_connection_info())  return( verrori );

    mysql_init(&mysql_read);
    if (!(mysql_real_connect(&mysql_read, MYSQL_READ_SERVER, 
            MYSQL_READ_USER, MYSQL_READ_PASSWD, MYSQL_READ_DATABASE, 
            MYSQL_READ_PORT, NULL, 0))) {
        /* we could not connect, at least try the update server */
        if (!(mysql_real_connect(&mysql_read, MYSQL_UPDATE_SERVER, 
            MYSQL_UPDATE_USER, MYSQL_UPDATE_PASSWD, MYSQL_UPDATE_DATABASE,
            MYSQL_READ_PORT, NULL, 0))) {

            snprintf(sqlerr, MAX_BUFF,
                     "   Can not connect to read database - %s\n", 
                     mysql_error( &mysql_update ));
#ifdef SHOW_TRACE
            snprintf( SqlBufUpdate, SQL_BUF_SIZE, 
                     "   mysql_real_connect - Server %s  User %s  "
                     "Password: %s Base: NULL Port: %s ?:NULL\n", 
                     MYSQL_READ_SERVER, MYSQL_READ_USER, 
                     MYSQL_READ_PASSWD, MYSQL_READ_PORT);
#else
            snprintf( SqlBufUpdate, SQL_BUF_SIZE, 
                     "   mysql_real_connect( - Server %s  User %s  "
                     "Password: *** Base: NULL Port: %i ?:NULL )\n", 
                     MYSQL_READ_SERVER, MYSQL_READ_USER, 
                     MYSQL_READ_PORT);
            last_query = SqlBufUpdate;
#endif
            verrori = VA_NO_AUTH_CONNECTION;
    
#ifdef SHOW_TRACE
            last_query = SqlBufUpdate;
            fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
            if( showerrors ) {
                vsqlerror( stderr, "Opening SQL read connection" );
            }
            return( verrori );
        }
    }

    /* return success */
    return(0);
}
#else
#define vauth_open_read vauth_open_update
#endif

//  Make vauth_open_read answer for vauth_open, so that function
//  can be called to test the database.

int vauth_open() {

#ifdef SHOW_TRACE
    fprintf( stderr, "vauth_open()\n");
#endif 

    return( vauth_open_read());

}

/************************************************************************
 *
 * Open a connection to the database for read-only queries
 */

int vauth_open_read_getall()
{

    /* if we are already connected, just return */
    if ( read_getall_open != 0 ) return(0);
    read_getall_open = 1;
    
//#ifdef SHOW_TRACE
    fprintf( stderr, "open_read_getall()\n" );
//#endif

    /* connect to mysql and set the database */
    if( load_connection_info())  return( verrori );

    mysql_init(&mysql_read_getall);
    if (!(mysql_real_connect(&mysql_read_getall, MYSQL_READ_SERVER, 
            MYSQL_READ_USER, MYSQL_READ_PASSWD, MYSQL_READ_DATABASE, 
            MYSQL_READ_PORT, NULL, 0))) {
        /* we could not connect, at least try the update server */
        if (!(mysql_real_connect(&mysql_read_getall, MYSQL_UPDATE_SERVER, 
            MYSQL_UPDATE_USER, MYSQL_UPDATE_PASSWD, MYSQL_UPDATE_DATABASE, 
            MYSQL_UPDATE_PORT, NULL, 0))) {

            snprintf(sqlerr, MAX_BUFF,
                     "   Can not connect to getall database - %s\n", 
                     mysql_error( &mysql_update ));
#ifdef SHOW_TRACE
            snprintf( SqlBufUpdate, SQL_BUF_SIZE, 
                     "   mysql_real_connect - Server %s  User %s  "
                     "Password: %s Base: NULL Port: %s ?:NULL\n", 
                     MYSQL_READ_SERVER, MYSQL_READ_USER, 
                     MYSQL_READ_PASSWD, MYSQL_READ_PORT);
#else
            snprintf( SqlBufUpdate, SQL_BUF_SIZE, 
                     "   mysql_real_connect( - Server %s  User %s  "
                     "Password: *** Base: NULL Port: %i ?:NULL )\n", 
                     MYSQL_READ_SERVER, MYSQL_READ_USER, 
                     MYSQL_READ_PORT);
            last_query = SqlBufUpdate;
#endif
            verrori = VA_NO_AUTH_CONNECTION;
    
#ifdef SHOW_TRACE
            last_query = SqlBufUpdate;
            fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
            if( showerrors ) {
                vsqlerror( stderr, "Opening SQL read-getall connection" );
            }
            return( verrori );
        }
    }

    /* return success */
    return(0);
}

/************************************************************************
 *
 *  vauth_create_table
 */

int vauth_create_table (char *table, char *layout)
{
 static char SqlBufCreate[SQL_BUF_SIZE];

#ifdef SHOW_TRACE
    fprintf( stderr, 
             "vauth_create_table( table: %s layout: %s showerror: %i)\n",
             table, layout, showerror );
#endif

  if (vauth_open_update()) return (verrori);

  snprintf (SqlBufCreate, SQL_BUF_SIZE, "CREATE TABLE %s ( %s )", table, layout);
#ifdef SHOW_QUERY
  fprintf( stderr, "vauth_create_table query\n%s\n", SqlBufCreate );
#endif

  if (mysql_query (&mysql_update, SqlBufCreate)) {
    snprintf(sqlerr, MAX_BUFF, 
             "   Unable to create table %s - %s\n", 
             table, mysql_error( &mysql_update ));
    last_query = SqlBufCreate;
    verrori = VA_CANNOT_CREATE_TABLE;

#ifdef SHOW_TRACE
    fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
    if( showerrors ) {
        vsqlerror( stderr, "Creating table" );
    }
    return( verrori );
  }

  return 0;
}
 
/************************************************************************
 *
 *  vauth_adddomain
 */

int vauth_adddomain( char *domain )
{
#ifdef SHOW_TRACE
    fprintf( stderr, "vauth_adddomain( %s )\n", domain );
#endif

#ifndef MANY_DOMAINS
  vset_default_domain( domain );
  vauth_create_table (vauth_munch_domain( domain ), TABLE_LAYOUT, 1);
#else
  /* if creation fails, don't show an error */
  vauth_create_table (MYSQL_DEFAULT_TABLE, TABLE_LAYOUT);
  if( verrori == VA_QUERY_FAILED ) verrori = 0;
#endif
  return( verrori );
}

/************************************************************************
 *
 *  vauth_adduser
 */

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
    
#ifdef SHOW_TRACE
    fprintf( stderr, "vauth_adduser( user: %s domain: %s pass: %s "
                     "gecos %s dir %s apop %i )\n", 
                     user, domain, pass, gecos, dir, apop );
#endif

    if (vauth_open_update()) return (verrori);
    vset_default_domain( domain );

    strncpy( quota, "NOQUOTA", 30 );

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

    qnprintf( SqlBufUpdate, SQL_BUF_SIZE, INSERT, 
      domstr, user, 
#ifdef MANY_DOMAINS
      domain,
#endif
      Crypted, apop, gecos, dirbuf, quota
#ifdef CLEAR_PASS
, pass
#endif
);

#ifdef SHOW_QUERY
     fprintf( stderr, "vauth_adduser query\n%s\n", SqlBufUpdate );
#endif
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        snprintf(sqlerr, MAX_BUFF, 
                 "   Unable to add user %s@%s - %s\n", 
                 domstr, user, mysql_error( &mysql_update ));
        last_query = SqlBufUpdate;
        verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
        fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
        if( showerrors ) {
            vsqlerror( stderr, "Adding user" );
        }
        return( verrori );
    } 

    return(0);

}


/************************************************************************
 *
 *  vauth_getpw
 */

struct vqpasswd *vauth_getpw(char *user, char *domain)
{
 char *domstr;
 static struct vqpasswd vpw;
 static char in_domain[156];
 uid_t myuid;
 uid_t uid;
 gid_t gid;

#ifdef SHOW_TRACE
    fprintf( stderr, "vauth_getpw( user: %s domain: %s )\n",
                     user, domain );
#endif

    vget_assign(domain,NULL,0,&uid,&gid);

    myuid = geteuid();
    if ( myuid != 0 && myuid != uid ) return(NULL);

    verrori = 0;
    if( vauth_open_read()) return( NULL );

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

    qnprintf(SqlBufRead, SQL_BUF_SIZE, USER_SELECT, domstr, user
#ifdef MANY_DOMAINS
, in_domain
#endif
);
#ifdef SHOW_QUERY
     fprintf( stderr, "vauth_getpw query\n%s\n", SqlBufRead );
#endif
    if (mysql_query(&mysql_read,SqlBufRead)) {
        snprintf(sqlerr, MAX_BUFF, 
                 "   Unable to retrieve user information - %s\n", 
                 mysql_error( &mysql_update ));
        last_query = SqlBufRead;
        verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
        fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
        fprintf(stderr, "vmysql: sql error[3]: %s\n", mysql_error(&mysql_read));
        if( showerrors ) {
            vsqlerror( stderr, "Getpw query" );
        }
        return(NULL);
    }

    if (!(res_read = mysql_store_result(&mysql_read))) {
        snprintf(sqlerr, MAX_BUFF, 
                 "   vautn_getpw - %s\n", 
                 mysql_error( &mysql_update ));
        last_query = SqlBufRead;
        verrori = VA_STORE_RESULT_FAILED;

#ifdef SHOW_TRACE
        fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
        if( showerrors ) {
            vsqlerror( stderr, "Getpw read" );
        }
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

    vlimits_setflags (&vpw, in_domain);

#ifdef DUMP_DATA
    fprintf( stderr, 
             "   vauth_getpw returned: \n"
             "      name: %s pass: %s uid %i gid %i\n"
             "      gecos: %s clear pw: %s shell: %s\ndir: %s\n\n",
             vpw.pw_name, vpw.pw_passwd, vpw.pw_uid, vpw.pw_gid,
             vpw.pw_gecos, vpw.pw_clear_passwd, vpw.pw_shell, vpw.pw_dir );
#endif

    return(&vpw);
}

/************************************************************************
 *
 * del a domain from the auth backend
 * - drop the domain's table, or del all users from users table
 * - delete domain's entries from lastauth table
 * - delete domain's limit's entries
 */

int vauth_deldomain( char *domain )
{
 char *tmpstr;
    
#ifdef SHOW_TRACE
    fprintf( stderr, "vauth_deldomain( %s )\n", domain );
#endif

    if (vauth_open_update()) return (verrori);
    vset_default_domain( domain );

#ifndef MANY_DOMAINS
    /* convert the domain name to the table name (eg convert . to _ ) */
    tmpstr = vauth_munch_domain( domain );
    snprintf( SqlBufUpdate, SQL_BUF_SIZE, "drop table %s", tmpstr);
#else
    tmpstr = MYSQL_DEFAULT_TABLE;
    qnprintf( SqlBufUpdate, SQL_BUF_SIZE, "delete from %s where pw_domain = '%s'",
        tmpstr, domain );
#endif 

#ifdef SHOW_QUERY
     fprintf( stderr, "vauth_deldomain - delete query\n%s\n", SqlBufUpdate );
#endif
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        snprintf(sqlerr, MAX_BUFF, 
                 "   Unablet to delete domain %s - %s\n", 
                 domain, mysql_error( &mysql_update ));
        last_query = SqlBufUpdate;
        verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
        fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
        if( showerrors ) {
            vsqlerror( stderr, "vdeldomain - delete domain" );
        }
        return( verrori );
    } 

#ifdef VALIAS 
    valias_delete_domain( domain);
#endif

#ifdef ENABLE_AUTH_LOGGING
    qnprintf( SqlBufUpdate, SQL_BUF_SIZE, 
        "delete from lastauth where domain = '%s'", domain );
#ifdef SHOW_QUERY
     fprintf( stderr, "vauth_deldomain - delete lastauth entry\n%s\n", SqlBufUpdate );
#endif
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        snprintf(sqlerr, MAX_BUFF, 
                 "   Unable to delete domain lastauth %s - %s\n", 
                 domain, mysql_error( &mysql_update ));
        last_query = SqlBufUpdate;
        verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
        fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
        if( showerrors ) {
            vsqlerror( stderr, "vdeldomain - delete lastauth" );
        }
        return( verrori );
    } 
#endif

    vdel_limits(domain);

    return(0);
}

/************************************************************************
 *
 *  vauth_deluser
 */

int vauth_deluser( char *user, char *domain )
{
 char *tmpstr;
    
#ifdef SHOW_TRACE
    fprintf( stderr, "vauth_deluser( user: %s domain: %s )\n",
                     user, domain );
#endif

    if (vauth_open_update()) return (verrori);
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

    qnprintf( SqlBufUpdate,  SQL_BUF_SIZE, DELETE_USER, tmpstr, user
#ifdef MANY_DOMAINS
, domain
#endif
 );
#ifdef SHOW_QUERY
     fprintf( stderr, "vauth_deluser - delete query\n%s\n", SqlBufUpdate );
#endif
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        snprintf(sqlerr, MAX_BUFF, 
                 "   Unable to delete user %s@%s - %s\n", 
                 user, domain, mysql_error( &mysql_update ));
        last_query = SqlBufUpdate;
        verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
        fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
    } 

#ifdef ENABLE_AUTH_LOGGING
    qnprintf( SqlBufUpdate, SQL_BUF_SIZE, 
              "delete from lastauth where user = '%s' and domain = '%s'", 
              user, domain );
#ifdef SHOW_QUERY
    fprintf( stderr, "vauth_deluser - delete lastauth query\n%s\n", SqlBufUpdate );
#endif

    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        snprintf(sqlerr, MAX_BUFF, 
                 "   Unable to delete user %s@%s lastauth - %s\n", 
                 user, domain, mysql_error( &mysql_update ));
        last_query = SqlBufUpdate;
        verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
        fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
    } 
#endif
    if( verrori && showerrors ) {
        vsqlerror( stderr, "vdeluser" );
    }
    return(verrori);
}

/************************************************************************
 *
 *  vauth_setquota
 */

int vauth_setquota( char *username, char *domain, char *quota)
{
 char *tmpstr;

#ifdef SHOW_TRACE
    fprintf( stderr, "vauth_setquota( user: %s domain: %s quota %s )\n",
                     username, domain, quota );
#endif

    if ( strlen(username) > MAX_PW_NAME ) return(VA_USER_NAME_TOO_LONG);
#ifdef USERS_BIG_DIR
    if ( strlen(username) == 1 ) return(VA_ILLEGAL_USERNAME);
#endif
    if ( strlen(domain) > MAX_PW_DOMAIN ) return(VA_DOMAIN_NAME_TOO_LONG);
    if ( strlen(quota) > MAX_PW_QUOTA )    return(VA_QUOTA_TOO_LONG);
    
    if (vauth_open_update()) return (verrori);
    vset_default_domain( domain );

#ifndef MANY_DOMAINS
    tmpstr = vauth_munch_domain( domain );
#else
    tmpstr = MYSQL_DEFAULT_TABLE; 
#endif

    qnprintf( SqlBufUpdate, SQL_BUF_SIZE, SETQUOTA, tmpstr, quota, username
#ifdef MANY_DOMAINS
, domain
#endif
);

#ifdef SHOW_QUERY
     fprintf( stderr, "vauth_setquota\n%s\n", SqlBufUpdate );
#endif
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
fprintf(stderr, "vmysql: sql error[4]: %s\n", mysql_error(&mysql_update));
        snprintf(sqlerr, MAX_BUFF, 
                 "   Unable to set quota %s@%s - %s\n", 
                 username, domain, mysql_error( &mysql_update ));
        last_query = SqlBufUpdate;
        verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
        fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
        if( showerrors ) {
            vsqlerror( stderr, "setting quota" );
        }
        return( verrori );
    } 
    return(0);
}

/************************************************************************
 *
 *  vauth_getall
 */

struct vqpasswd *vauth_getall(char *domain, int first, int sortit)
{
 char *domstr = NULL;
 static struct vqpasswd vpw;
 static int more = 0;

#ifdef SHOW_TRACE
    fprintf( stderr, "vauth_getall( domain: %s first: %i sortit %i)\n",
                     domain, first, sortit );
#endif

    vset_default_domain( domain );

#ifdef MANY_DOMAINS
    domstr = MYSQL_DEFAULT_TABLE; 
#else
    domstr = vauth_munch_domain( domain );
#endif

    if ( first == 1 ) {
        if( vauth_open_read_getall()) return( NULL );

        qnprintf(SqlBufRead,  SQL_BUF_SIZE, GETALL, domstr
#ifdef MANY_DOMAINS
            ,domain
#endif
            );

        if ( sortit == 1 ) {
            strncat( SqlBufRead, " order by pw_name", SQL_BUF_SIZE);
        }

        if (res_read!=NULL) mysql_free_result(res_read_getall);
        res_read = NULL;

#ifdef SHOW_QUERY
        fprintf( stderr, "vqpasswd query\n%s\n", SqlBufRead );
#endif
        if (mysql_query(&mysql_read_getall,SqlBufRead)) {
            snprintf(sqlerr, MAX_BUFF, 
                     "   Unable to vauth_getall domain %s - %s\n", 
                     domain, mysql_error( &mysql_update ));
            last_query = SqlBufRead;
            verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
            fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
            if( showerrors ) {
                vsqlerror( stderr, "vauth get all query" );
            }
            return( NULL );
        }

        if (!(res_read_getall=mysql_store_result(&mysql_read_getall))) {
            snprintf(sqlerr, MAX_BUFF, 
                     "   vauth_getall - %s\n", 
                     mysql_error( &mysql_update ));
            last_query = SqlBufRead;
            verrori = VA_STORE_RESULT_FAILED;

#ifdef SHOW_TRACE
            fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
            fprintf(stderr, "vmysql: store result failed 2\n");
            if( showerrors ) {
                vsqlerror( stderr, "vauth get all read" );
            }
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

#ifdef DUMP_DATA
    fprintf( stderr, "   name: %s pass: %s uid %i gid %i gecos: %s\n"
                     "   clear pw: %s, shell: %s\n   dir: %s\n\n",
                     vpw.pw_name, vpw.pw_passwd, vpw.pw_uid, vpw.pw_gid,
                     vpw.pw_gecos, vpw.pw_clear_passwd, vpw.pw_shell, 
                     vpw.pw_dir );
#endif

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

/************************************************************************
 *
 *  vauth_munch_domain
 */

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

#ifdef SHOW_TRACE
    fprintf( stderr, "vauth_setpw( inpw{ name: %s pass: %s "
                     "uid %i gid %i gecos: %s clear pw: %s, "
                     "shell: %s\ndir: %s }, domain: %s )\n\n",
                     inpw->pw_name, inpw->pw_passwd, inpw->pw_uid, 
                     inpw->pw_gid, inpw->pw_gecos, inpw->pw_clear_passwd,
                     inpw->pw_shell, inpw->pw_dir, domain );
#endif

    err = vcheck_vqpw(inpw, domain);
    if ( err != 0 ) return(err);

    vget_assign(domain,NULL,0,&uid,&gid);
    myuid = geteuid();
    if ( myuid != 0 && myuid != uid ) {
        return(VA_BAD_UID);
    }

    if (vauth_open_update()) return (verrori);
    vset_default_domain( domain );

#ifndef MANY_DOMAINS
    tmpstr = vauth_munch_domain( domain );
#else
    tmpstr = MYSQL_DEFAULT_TABLE; 
#endif

    qnprintf( SqlBufUpdate,SQL_BUF_SIZE,SETPW,
            tmpstr, 
            inpw->pw_passwd,
            inpw->pw_uid,
            inpw->pw_gid, 
            inpw->pw_gecos,
            inpw->pw_dir, 
            inpw->pw_shell, 
#ifdef CLEAR_PASS
            inpw->pw_clear_passwd,
#endif
            inpw->pw_name
#ifdef MANY_DOMAINS
            ,domain
#endif
            );

#ifdef SHOW_QUERY
     fprintf( stderr, "vauth_setpw query\n%s\n", SqlBufUpdate );
#endif
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        snprintf(sqlerr, MAX_BUFF, 
                 "   vauthsetpw failed - %s\n", 
                 mysql_error( &mysql_update ));
        last_query = SqlBufUpdate;
        verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
        fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
        if( showerrors )  {
            vsqlerror( stderr, "vauth setpw" );
        }
        return( verrori );
    } 

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
 int rows;

#ifdef SHOW_TRACE
    fprintf( stderr, "vopen_smtp_relay()\n");
#endif

    mytime = time(NULL);
    ipaddr = get_remote_ip();
    if ( ipaddr == NULL ) {
        return 0;
    }

    if (vauth_open_update()) return (verrori);

    qnprintf( SqlBufUpdate, SQL_BUF_SIZE,
"replace into relay ( ip_addr, timestamp ) values ( '%s', %d )",
            ipaddr, (int)mytime);
#ifdef SHOW_QUERY
     fprintf( stderr, "vpopn_smtp_relay query\n%s\n", SqlBufUpdate );
#endif
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        vcreate_relay_table();
#ifdef SHOW_QUERY
     fprintf( stderr, "\n%s\n", SqlBufUpdate );
#endif
        if (mysql_query(&mysql_update,SqlBufUpdate)) {
            snprintf(sqlerr, MAX_BUFF, 
                     "   vopen_smtp_relay - %s\n", 
                     mysql_error( &mysql_update ));
            last_query = SqlBufUpdate;
            verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
            fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
            if( showerrors )  {
                vsqlerror( stderr, "open smtp relay" );
            }
            return( verrori );
        }
    }
    rows = mysql_affected_rows(&mysql_update);

    /* return true if only INSERT (didn't exist) */
    /* would return 2 if replaced, or -1 if error */
    return rows == 1;
}

/************************************************************************
 *
 *  vupdate_rules
 */

void vupdate_rules(int fdm)
{
#ifdef SHOW_TRACE
    fprintf( stderr, "vopen_smtp_relay( fdm: %i )\n", fdm );
#endif

    if( vauth_open_read()) return;

    snprintf(SqlBufRead, SQL_BUF_SIZE, "select ip_addr from relay");
#ifdef SHOW_QUERY
     fprintf( stderr, "vupdate_rules query\n%s\n", SqlBufRead );
#endif
    if (mysql_query(&mysql_read,SqlBufRead)) {
        vcreate_relay_table();
        if (mysql_query(&mysql_read,SqlBufRead)) {
            snprintf(sqlerr, MAX_BUFF, 
                     "   Update rules failed  - %s\n", 
                     mysql_error( &mysql_update ));
            last_query = SqlBufRead;
            verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
            fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
            if( showerrors )  {
                vsqlerror( stderr, "update rules query" );
            }
            return;
        }
    }
    if (!(res_read = mysql_store_result(&mysql_read))) {
        snprintf(sqlerr, MAX_BUFF, 
                 "   update_rules - %s\n", 
                 mysql_error( &mysql_update ));
        last_query = SqlBufRead;
        verrori = VA_STORE_RESULT_FAILED;

#ifdef SHOW_TRACE
        fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
        if( showerrors )  {
            vsqlerror( stderr, "update rules read" );
        }
        return;
    }
    while((row = mysql_fetch_row(res_read))) {
        snprintf(SqlBufRead, SQL_BUF_SIZE, "%s:allow,RELAYCLIENT=\"\",RBLSMTPD=\"\"\n", row[0]);
#ifdef DUMP_DATA
        fprintf( stderr, "\n%s\n", SqlBufRead );
#endif
        write(fdm,SqlBufRead, strlen(SqlBufRead));
    }
    mysql_free_result(res_read);

}

/************************************************************************
 *
 *  vclear_open_smtp
 */

void vclear_open_smtp(time_t clear_minutes, time_t mytime)
{
 time_t delete_time;
    
#ifdef SHOW_TRACE
    fprintf( stderr, 
             "vclear_open_smtp( clear_minutes: %i, mytime: %i )\n", 
              (int) clear_minutes, (int) mytime );
#endif

    if (vauth_open_update()) return;
    delete_time = mytime - clear_minutes;

    snprintf( SqlBufUpdate, SQL_BUF_SIZE, "delete from relay where timestamp <= %d", 
        (int)delete_time);
#ifdef SHOW_QUERY
     fprintf( stderr, "vclear_open_smtp query\n%s\n", SqlBufUpdate );
#endif
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        vcreate_relay_table();
        return;
    }
}

/************************************************************************
 *
 *  vcreate_relay_table
 */

void vcreate_relay_table()
{
#ifdef SHOW_TRACE
    fprintf( stderr, "vcreate_relay_table()\n");
#endif

  vauth_create_table ("relay", RELAY_TABLE_LAYOUT);
}
#endif

/************************************************************************
 *
 *  vmkpasswd
 */

int vmkpasswd( char *domain )
{
#ifdef SHOW_TRACE
    fprintf( stderr, "vmkpasswd( domain: %s )\n", domain );
#endif

    return(0);
}

/************************************************************************
 *
 *  vclose
 */

void vclose()
{
#ifdef SHOW_TRACE
    fprintf( stderr, "vclose()\n" );
#endif

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
#ifdef SHOW_TRACE
    fprintf( stderr, "vcreate_ip_map_table()\n" );
#endif

  vauth_create_table ("ip_alias_map", IP_ALIAS_TABLE_LAYOUT);
}

/************************************************************************
 *
 *  vget_ip_map
 */

int vget_ip_map( char *ip, char *domain, int domain_size)
{
#ifdef SHOW_TRACE
    fprintf( stderr, 
             "vget_ip_map( ip: %s domain: {return value} )\n",
             ip );
#endif

 int ret = -1;

    if ( ip == NULL || strlen(ip) <= 0 ) return(VA_INVALID_IP_ADDRESS);
    if ( domain == NULL ) return(VA_INVALID_DOMAIN_NAME);
    if ( vauth_open_read() ) return(verrori);

    qnprintf(SqlBufRead, SQL_BUF_SIZE, 
             "select domain from ip_alias_map where ip_addr = '%s'",
             ip);
#ifdef SHOW_QUERY
     fprintf( stderr, "vget_ip_map query\n%s\n", SqlBufRead );
#endif
    if (mysql_query(&mysql_read,SqlBufRead)) {
        snprintf(sqlerr, MAX_BUFF, 
                 "   vget_ip_map failed for IP %s - %s\n", 
                 ip, mysql_error( &mysql_update ));
        last_query = SqlBufUpdate;
        verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
        fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
        if( showerrors )  {
            vsqlerror( stderr, "Get IP map query" );
        }
        return( verrori );
    }

    if (!(res_read = mysql_store_result(&mysql_read))) {
        snprintf(sqlerr, MAX_BUFF, 
                 "   vget_ip_map - %s\n", 
                 mysql_error( &mysql_update ));
        last_query = SqlBufRead;
        verrori = VA_STORE_RESULT_FAILED;

#ifdef SHOW_TRACE
        fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
        if( showerrors )  {
            vsqlerror( stderr, "Get IP map read" );
        }
        return(verrori);
    }
    while((row = mysql_fetch_row(res_read))) {
        ret = 0;
        strncpy(domain, row[0], domain_size);
    }
    mysql_free_result(res_read);

#ifdef DUMP_DATA
    fprintf( stderr, "   Returned domain: %s\n\n", domain );
#endif

    return(ret);
}

/************************************************************************
 *
 *  vadd_ip_map
 */

int vadd_ip_map( char *ip, char *domain) 
{
    if ( ip == NULL || strlen(ip) <= 0 ) return(-1);
    if ( domain == NULL || strlen(domain) <= 0 ) return(-1);
    if (vauth_open_update()) return (verrori);

    qnprintf(SqlBufUpdate,SQL_BUF_SIZE,  
      "replace into ip_alias_map ( ip_addr, domain ) values ( '%s', '%s' )",
      ip, domain);
#ifdef SHOW_QUERY
      fprintf( stderr, "vadd_ip_map query\n%s\n", SqlBufUpdate );
#endif
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        vcreate_ip_map_table();
#ifdef SHOW_QUERY
        fprintf( stderr, "vadd_ip_map retry\n%s\n", SqlBufUpdate );
#endif
        if (mysql_query(&mysql_update,SqlBufUpdate)) {
            snprintf(sqlerr, MAX_BUFF, 
                     "   vadd_ip_map ( ip: %s domain: %s ) failed - %s\n", 
                     ip, domain, mysql_error( &mysql_update ));
            last_query = SqlBufUpdate;
            verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
            fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
            if( showerrors )  {
                vsqlerror( stderr, "Add IP map" );
            }
            return( verrori );
        }
    }
    return(0);
}

/************************************************************************
 *
 *  vdel_ip_map
 */

int vdel_ip_map( char *ip, char *domain) 
{
#ifdef SHOW_TRACE
    fprintf( stderr, "vadd_ip_map( ip: %s domain: %s )\n",
                     ip, domain );
#endif

    if ( ip == NULL || strlen(ip) <= 0 ) return(-1);
    if ( domain == NULL || strlen(domain) <= 0 ) return(-1);
    if (vauth_open_update()) return (verrori);

    qnprintf( SqlBufUpdate,SQL_BUF_SIZE,  
        "delete from ip_alias_map where ip_addr = '%s' and domain = '%s'",
            ip, domain);
#ifdef SHOW_QUERY
     fprintf( stderr, "vdel_ip_map\n%s\n", SqlBufUpdate );
#endif
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        snprintf(sqlerr, MAX_BUFF, 
                 "   vdel_ip_map ( ip: %s domain: %s ) failed - %s\n", 
                 ip, domain, mysql_error( &mysql_update ));
        last_query = SqlBufUpdate;
        verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
        fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
        if( showerrors ) {
            vsqlerror( stderr, "Del IP map" );
        }
        return( verrori );
    } 
    return(0);
}

/************************************************************************
 *
 *  vshow_ip_map
 */

int vshow_ip_map( int first, char *ip, char *domain )
{
 static int more = 0;

#ifdef SHOW_TRACE
    fprintf( stderr, 
             "vshow_ip_map( first: %i ip: {return} domain: {Return} )\n",
             first );
#endif

    if ( ip == NULL || strlen(ip) <= 0 ) return(VA_INVALID_IP_ADDRESS);
    if ( domain == NULL ) return(VA_INVALID_DOMAIN_NAME);
    if ( vauth_open_read() ) return(verrori);

    if ( first == 1 ) {

        snprintf(SqlBufRead,SQL_BUF_SIZE, 
            "select ip_addr, domain from ip_alias_map"); 

        if (res_read!=NULL) mysql_free_result(res_read);
        res_read = NULL;

#ifdef SHOW_QUERY
     fprintf( stderr, "vshow_ip_map query\n%s\n", SqlBufRead );
#endif
        if (mysql_query(&mysql_read,SqlBufRead)) {
            vcreate_ip_map_table();
            if (mysql_query(&mysql_read,SqlBufRead)) {
                snprintf(sqlerr, MAX_BUFF, 
                         "   vshow_ip_map ( domain: %s ) failed - %s\n", 
                         domain, mysql_error( &mysql_update ));
                snprintf(sqlerr, MAX_BUFF, 
                         "   - %s\n", 
                         domstr, user, mysql_error( &mysql_update ));
                last_query = SqlBufUpdate;
                verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
                fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
                if( showerrors )  {
                    vsqlerror( stderr, "Show IP map query" );
                }
                return(0);
            }
        }

        if (!(res_read = mysql_store_result(&mysql_read))) {
            snprintf(sqlerr, MAX_BUFF, 
                     "   vshow_ip_map - %s\n", 
                     mysql_error( &mysql_update ));
            last_query = SqlBufRead;
            verrori = VA_STORE_RESULT_FAILED;

#ifdef SHOW_TRACE
            fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
            if( showerrors )  {
                vsqlerror( stderr, "Show IP map read" );
            }
            return(0);
        }
    } else if ( more == 0 ) {
        return(0);
    }

    if ((row = mysql_fetch_row(res_read)) != NULL) {
        strncpy(ip, row[0], 18); 
        strncpy(domain, row[1], 156); 
        more = 1;
#ifdef DUMP_DATA
        fprintf( stderr, "   Returned ip: %s domain: %s\n\n", 
                 ip, domain );
#endif

        return(1);
    }
    more = 0;
    mysql_free_result(res_read);
    res_read = NULL;
    return(0);
}
#endif

/************************************************************************
 *
 *  vread_dir_control
 */

int vread_dir_control(vdir_type *vdir, char *domain, uid_t uid, gid_t gid)
{
 int found = 0;

#ifdef SHOW_TRACE
    fprintf( stderr, "vread_dir_control( domain: %s uid: %i gid %i )\n",
                     domain, uid, gid );
#endif

    if ( vauth_open_read() ) return(verrori);
    qnprintf(SqlBufRead, SQL_BUF_SIZE, 
        "select %s from dir_control where domain = '%s'", 
        DIR_CONTROL_SELECT, domain );
#ifdef SHOW_QUERY
        fprintf( stderr, "vread_dir_control query\n%s\n", SqlBufRead );
#endif
    if (mysql_query(&mysql_read,SqlBufRead)) {
        vcreate_dir_control(domain);
        qnprintf(SqlBufRead, SQL_BUF_SIZE, 
            "select %s from dir_control where domain = '%s'", 
           DIR_CONTROL_SELECT, domain );
#ifdef SHOW_QUERY
           fprintf( stderr, "vread_dir_control retry\n%s\n", SqlBufRead );
#endif
        if (mysql_query(&mysql_read,SqlBufRead)) {
            snprintf(sqlerr, MAX_BUFF, 
                     "   vread_dir_control failed %s - %s\n", 
                     domain, mysql_error( &mysql_update ));
            last_query = SqlBufRead;
            verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
            fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
            if( showerrors )  {
                vsqlerror( stderr, "Read dir control query" );
            }
            return( verrori );
        }
    }
    if (!(res_read = mysql_store_result(&mysql_read))) {
        snprintf(sqlerr, MAX_BUFF, 
                 "   vread_dircontrol - %s\n", 
                 mysql_error( &mysql_update ));
        last_query = SqlBufRead;
        verrori = VA_STORE_RESULT_FAILED;

#ifdef SHOW_TRACE
        fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
        fprintf(stderr, "vread_dir_control: store result failed 6\n");
        if( showerrors )  {
            vsqlerror( stderr, "Read dir control read" );
        }
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

#ifdef DUMP_DATA
    fprintf( stderr, "   curr_users:\t%li\n", vdir->cur_users );
    fprintf( stderr, "   level_curr:\t%i\n", vdir->level_cur );
    fprintf( stderr, "   level_max:\t%i\n", vdir->level_max );

    fprintf( stderr, "   level_start:\t%i\t%i\t%i\n", 
             vdir->level_start[0], vdir->level_start[1], 
             vdir->level_start[2] );

    fprintf( stderr, "   level_end:\t%i\t%i\t%i\n", 
             vdir->level_end[0], vdir->level_end[1], 
             vdir->level_end[2] );

    fprintf( stderr, "   level_mod:\t%i\t%i\t%i\n", 
             vdir->level_mod[0], vdir->level_mod[1], 
             vdir->level_mod[2] );

    fprintf( stderr, "   level_index:\t%i\t%i\t%i\n", 
             vdir->level_index[0], vdir->level_index[1], 
             vdir->level_index[2] );
#endif
    return(0);
}

/************************************************************************
 *
 *  vwrite_dir_control
 */

int vwrite_dir_control(vdir_type *vdir, char *domain, uid_t uid, gid_t gid)
{
#ifdef SHOW_TRACE
    fprintf( stderr, "vwrite_dir_control( domain: %s uid: %i gid %i )\n",
                     domain, uid, gid );
#endif

    if (vauth_open_update()) return (verrori);

    qnprintf(SqlBufUpdate, SQL_BUF_SIZE, "replace into dir_control ( \
domain, cur_users, \
level_cur, level_max, \
level_start0, level_start1, level_start2, \
level_end0, level_end1, level_end2, \
level_mod0, level_mod1, level_mod2, \
level_index0, level_index1, level_index2, the_dir ) values ( \
'%s', %lu, %d, %d, \
%d, %d, %d, \
%d, %d, %d, \
%d, %d, %d, \
%d, %d, %d, \
'%s')\n",
    domain, vdir->cur_users, vdir->level_cur, vdir->level_max,
    vdir->level_start[0], vdir->level_start[1], vdir->level_start[2],
    vdir->level_end[0], vdir->level_end[1], vdir->level_end[2],
    vdir->level_mod[0], vdir->level_mod[1], vdir->level_mod[2],
    vdir->level_index[0], vdir->level_index[1], vdir->level_index[2],
    vdir->the_dir);

#ifdef SHOW_QUERY
    fprintf( stderr, "vwrite_dir_control query\n%s\n", SqlBufUpdate );
#endif
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        vcreate_dir_control(domain);
#ifdef SHOW_QUERY
        fprintf( stderr, "vwrite_dir_control retry\n%s\n", SqlBufUpdate );
#endif
        if (mysql_query(&mysql_update,SqlBufUpdate)) {
            snprintf(sqlerr, MAX_BUFF, 
                     "   write_dir_control failed %s - %s\n", 
                     domain, mysql_error( &mysql_update ));
            last_query = SqlBufUpdate;
            verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
            fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
            if( showerrors )  {
                vsqlerror( stderr, "Write dir control" );
            }
            return( verrori );
        }
    }

    return(0);
}

/************************************************************************
 *
 *  vcreate_dir_control
 */

void vcreate_dir_control(char *domain)
{
  if (vauth_create_table ("dir_control", DIR_CONTROL_TABLE_LAYOUT)) return;

    /* this next bit should be replaced with a call to vwrite_dir_control */
    qnprintf(SqlBufUpdate, SQL_BUF_SIZE, "replace into dir_control ( \
domain, cur_users, \
level_cur, level_max, \
level_start0, level_start1, level_start2, \
level_end0, level_end1, level_end2, \
level_mod0, level_mod1, level_mod2, \
level_index0, level_index1, level_index2, the_dir ) values ( \
'%s', 0, \
0, %d, \
0, 0, 0, \
%d, %d, %d, \
0, 2, 4, \
0, 0, 0, \
'')\n",
    domain, MAX_DIR_LEVELS, MAX_DIR_LIST-1, MAX_DIR_LIST-1, MAX_DIR_LIST-1);

#ifdef SHOW_QUERY
    fprintf( stderr, "vcreate_dir_control query\n%s\n", SqlBufUpdate );
#endif
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        snprintf(sqlerr, MAX_BUFF, 
                 "   vcreate_dir_control failed %s - %s\n", 
                 domain, mysql_error( &mysql_update ));
        last_query = SqlBufUpdate;
        verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
        fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
        if( showerrors )  {
            vsqlerror( stderr, "Create Dir control" );
        }
        return;
    }
}

/************************************************************************
 *
 *  vdel_dir_control
 */

int vdel_dir_control(char *domain)
{

#ifdef SHOW_TRACE
    fprintf( stderr, "vdel_dir_control( domain: %s )\n", domain );
#endif

    if (vauth_open_update()) return (verrori);

    qnprintf(SqlBufUpdate, SQL_BUF_SIZE, 
        "delete from dir_control where domain = '%s'", 
        domain); 
#ifdef SHOW_QUERY
        fprintf( stderr, "vdel_dir_control query\n%s\n", SqlBufUpdate );
#endif
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        vcreate_dir_control(domain);
#ifdef SHOW_QUERY
        fprintf( stderr, "vdel_dir_control retry\n%s\n", SqlBufUpdate );
#endif
            if (mysql_query(&mysql_update,SqlBufUpdate)) {
                snprintf(sqlerr, MAX_BUFF, 
                         "   vdel_dir_control failed %s - %s\n", 
                         domain, mysql_error( &mysql_update ));
                last_query = SqlBufUpdate;
                verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
                fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
                if( showerrors )  {
                    vsqlerror( stderr, "Delete dir control" );
                }
                return( verrori );
        }
    }

    return(0);
}

/************************************************************************
 *
 *  vset_lastauth
 */

#ifdef ENABLE_AUTH_LOGGING
int vset_lastauth(char *user, char *domain, char *remoteip )
{

    if (vauth_open_update()) return (verrori);

    qnprintf( SqlBufUpdate, SQL_BUF_SIZE,
"replace into lastauth set user='%s', domain='%s', \
remote_ip='%s', timestamp=%lu", user, domain, remoteip, time(NULL)); 
#ifdef SHOW_QUERY
    fprintf( stderr, "vset_lastauth query\n%s\n", SqlBufUpdate );
#endif
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        vcreate_lastauth_table();
#ifdef SHOW_QUERY
        fprintf( stderr, "vset_lastauth retry\n%s\n", SqlBufUpdate );
#endif
        if (mysql_query(&mysql_update,SqlBufUpdate)) {
            snprintf(sqlerr, MAX_BUFF, 
                     "   vset_lastauth %s@%s - %s\n", 
                     user, domain, mysql_error( &mysql_update ));
            last_query = SqlBufUpdate;
            verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
            fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
            if( showerrors )  {
                vsqlerror( stderr, "Set last auth" );
            }
            return( verrori );
        }
    }
    return(0);
}

/************************************************************************
 *
 *  vget_lastauth
 */

time_t vget_lastauth(struct vqpasswd *pw, char *domain)
{
 time_t mytime;

#ifdef SHOW_TRACE
    fprintf( stderr, "vget_lastauth( user: %s domain: %s )\n",
                     pw->pw_name, domain );
#endif

    if ( vauth_open_read() ) return(verrori);

    qnprintf( SqlBufRead,  SQL_BUF_SIZE,
    "select timestamp from lastauth where user='%s' and domain='%s'", 
        pw->pw_name, domain);
#ifdef SHOW_QUERY
    fprintf( stderr, "vget_lastauty query\n%s\n", SqlBufRead );
#endif
    if (mysql_query(&mysql_read,SqlBufRead)) {
        vcreate_lastauth_table();
#ifdef SHOW_QUERY
        fprintf( stderr, "vget_lastauth retry\n%s\n", SqlBufRead );
#endif
        if (mysql_query(&mysql_read,SqlBufRead)) {
            snprintf(sqlerr, MAX_BUFF, 
                     "   vget_lastauth failed - %s\n", 
                     mysql_error( &mysql_update ));
            last_query = SqlBufUpdate;
            verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
            fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
            if( showerrors )  {
                vsqlerror( stderr, "Get last auth query" );
            }
            return(0);
        }
    }
    if( !(res_read = mysql_store_result(&mysql_read))) {
        snprintf(sqlerr, MAX_BUFF, 
                 "   vget_lastauth - %s\n", 
                 mysql_error( &mysql_update ));
        last_query = SqlBufRead;
        verrori = VA_STORE_RESULT_FAILED;

#ifdef SHOW_TRACE
        fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
        if( showerrors )  {
            vsqlerror( stderr, "Get last auth read" );
        }
        return(0);

    }
    mytime = 0;
    while((row = mysql_fetch_row(res_read))) {
        mytime = atol(row[0]);
    }
    mysql_free_result(res_read);

#ifdef DUMP_DATA
//    need to do the cache changes first...
//    fprintf( stderr, "   Time: %i  IP: %s\n", 
//             (int)lastauthtime, lastauthip );
#endif

    return(mytime);
}

/************************************************************************
 *
 *  vget_lastauthip
 */

char *vget_lastauthip(struct vqpasswd *pw, char *domain)
{
 static char tmpbuf[100];

#ifdef SHOW_TRACE
    fprintf( stderr, "vget_lastauthip( user: %s domain: %s )\n",
                     pw->pw_name, domain );
#endif

    if ( vauth_open_read() ) return(NULL);

    qnprintf( SqlBufRead,  SQL_BUF_SIZE,
    "select remote_ip from lastauth where user='%s' and domain='%s'", 
        pw->pw_name, domain);
#ifdef SHOW_QUERY
    fprintf( stderr, "vget_lastauthip query\n%s\n", SqlBufRead );
#endif
    if (mysql_query(&mysql_read,SqlBufRead)) {
        vcreate_lastauth_table();
#ifdef SHOW_QUERY
        fprintf( stderr, "vget_lastauthip retry\n%s\n", SqlBufRead );
#endif
        if (mysql_query(&mysql_read,SqlBufRead)) {
            snprintf(sqlerr, MAX_BUFF, 
                     "   vget_alstauthip failed - %s\n", 
                     mysql_error( &mysql_update ));
            last_query = SqlBufRead;
            verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
            fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
            if( showerrors )  {
                vsqlerror( stderr, "Get last auth ip query" );
            }
            return(NULL);
        }
    }

    if( !(res_read = mysql_store_result(&mysql_read)))  {
        snprintf(sqlerr, MAX_BUFF, 
                 "   vget_lastauthip - %s\n", 
                 mysql_error( &mysql_update ));
        last_query = SqlBufRead;
        verrori = VA_STORE_RESULT_FAILED;

#ifdef SHOW_TRACE
        fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
        if( showerrors )  {
            vsqlerror( stderr, "Get last auth ip read" );
        }
        return(NULL);
    }

    while((row = mysql_fetch_row(res_read))) {
        strncpy(tmpbuf,row[0],100);
    }

    mysql_free_result(res_read);

#ifdef DUMP_DATA
//    need to do the cache changes first...
//    fprintf( stderr, "   Time: %i  IP: %s\n", 
//             (int)lastauthtime, lastauthip );
#endif

    return(tmpbuf);
}

/************************************************************************
 *
 *  vcreate_lastauth_table
 */

void vcreate_lastauth_table()
{
  vauth_create_table ("lastauth", LASTAUTH_TABLE_LAYOUT);
}
#endif /* ENABLE_AUTH_LOGGING */

/************************************************************************
 *
 *  valias_select
 */

#ifdef VALIAS
struct linklist *valias_current = NULL;
char *valias_select( char *alias, char *domain )
{
 struct linklist *temp_entry = NULL;

#ifdef SHOW_TRACE
    fprintf( stderr, "valias_select( alias: %s domain: %s )\n",
                     alias, domain );
#endif

    /* remove old entries as necessary */
    while (valias_current != NULL)
        valias_current = linklist_del (valias_current);

    /* if we can not connect, set the verrori value */
    if ( vauth_open_read() ) return(NULL);

    qnprintf( SqlBufRead, SQL_BUF_SIZE, "select valias_line from valias \
where alias = '%s' and domain = '%s'", alias, domain );

#ifdef SHOW_QUERY
    fprintf( stderr, "valias_select query\n%s\n", SqlBufRead );
#endif
    if (mysql_query(&mysql_read,SqlBufRead)) {
        vcreate_valias_table();
#ifdef SHOW_QUERY
        fprintf( stderr, "valias_select retry\n%s\n", SqlBufRead );
#endif
        if (mysql_query(&mysql_read,SqlBufRead)) {
            snprintf(sqlerr, MAX_BUFF, 
                     "   valias_select failed - %s\n", 
                     mysql_error( &mysql_update ));
            last_query = SqlBufRead;
            verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
            fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
            if( showerrors )  {
                vsqlerror( stderr, "valias_select query" );
            }
            return(NULL);
        }
    }
    if( !(res_read = mysql_store_result(&mysql_read)))  {
        snprintf(sqlerr, MAX_BUFF, 
                 "   valias_select - %s\n", 
                 mysql_error( &mysql_update ));
        last_query = SqlBufRead;
        verrori = VA_STORE_RESULT_FAILED;

#ifdef SHOW_TRACE
        fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
        if( showerrors )  {
            vsqlerror( stderr, "valias select read" );
        }
        return(NULL);
    }

    while ((row = mysql_fetch_row(res_read))) {
        temp_entry = linklist_add (temp_entry, row[0], "");
        if (valias_current == NULL) valias_current = temp_entry;
    }
    mysql_free_result (res_read);

    if (valias_current == NULL) return NULL; /* no results */
    else return(valias_current->data);
}

/************************************************************************
 *
 *  valias_select_next
 */

char *valias_select_next()
{
#ifdef SHOW_TRACE
    fprintf( stderr, "valias_select_next()\n");
#endif

    if (valias_current == NULL) return NULL;
 
    valias_current = linklist_del (valias_current);

    if (valias_current == NULL) return NULL;
    else {
#ifdef DUMP_DATA
        fprintf(stderr, "   %s\n", valias_current->data );
#endif
        return valias_current->data;
    }
}

int valias_insert( char *alias, char *domain, char *alias_line)
{

#ifdef SHOW_TRACE
    fprintf( stderr, "valias_insert( alias: %s domain: %s line: %s )\n",
             alias, domain, alias_line );
#endif

    if (vauth_open_update()) return (verrori);

    while(*alias_line==' ' && *alias_line!=0) ++alias_line;

    qnprintf( SqlBufUpdate, SQL_BUF_SIZE, "insert into valias \
( alias, domain, valias_line ) values ( '%s', '%s', '%s')",
        alias, domain, alias_line );

#ifdef SHOW_QUERY
    fprintf( stderr, "valias_insert query\n%s\n", SqlBufUpdate );
#endif
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        vcreate_valias_table();
#ifdef SHOW_QUERY
        fprintf( stderr, "valias_insert retry\n%s\n", SqlBufUpdate );
#endif
        if (mysql_query(&mysql_update,SqlBufUpdate)) {
            snprintf(sqlerr, MAX_BUFF, 
                     "   valias_insert failed - %s\n", 
                     mysql_error( &mysql_update ));
            last_query = SqlBufUpdate;
            verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
            fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
            if( showerrors )  {
                vsqlerror( stderr, "valias select next" );
            }
            return( verrori );
        }
    }
    return(0);
}

/************************************************************************
 *
 *  valias_remove
 */

int valias_remove( char *alias, char *domain, char *alias_line)
{

#ifdef SHOW_TRACE
    fprintf( stderr, "valias_remove( alias: %s domain: %s line: %s )\n",
                     alias, domain, alias_line );
#endif

    if (vauth_open_update()) return (verrori);

    qnprintf( SqlBufUpdate, SQL_BUF_SIZE, 
        "delete from valias where alias = '%s' \
and valias_line = '%s' and domain = '%s'", alias, alias_line, domain );

#ifdef SHOW_QUERY
    fprintf( stderr, "valias_remove query\n%s\n", SqlBufUpdate );
#endif
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        vcreate_valias_table();
#ifdef SHOW_QUERY
        fprintf( stderr, "valias_remove retry\n%s\n", SqlBufUpdate );
#endif
        if (mysql_query(&mysql_update,SqlBufUpdate)) {
            snprintf(sqlerr, MAX_BUFF, 
                     "   valias_remove failed - %s\n", 
                     mysql_error( &mysql_update ));
            last_query = SqlBufUpdate;
            verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
            fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
            if( showerrors )  {
                vsqlerror( stderr, "valias remove" );
            }
            return( verrori );
        }
    }
    return(0);
}

/************************************************************************
 *
 *  valias_delete
 */

int valias_delete( char *alias, char *domain)
{

#ifdef SHOW_TRACE
    fprintf( stderr, "valias_delete( alias: %s domain: %s )\n",
                     alias, domain );
#endif

    if (vauth_open_update()) return (verrori);

    qnprintf( SqlBufUpdate, SQL_BUF_SIZE, 
        "delete from valias where alias = '%s' \
and domain = '%s'", alias, domain );

#ifdef SHOW_QUERY
    fprintf( stderr, "valias_delete query\n%s\n", SqlBufUpdate );
#endif
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        vcreate_valias_table();
#ifdef SHOW_QUERY
        fprintf( stderr, "valias_delete retry\n%s\n", SqlBufUpdate );
#endif
        if (mysql_query(&mysql_update,SqlBufUpdate)) {
            snprintf(sqlerr, MAX_BUFF, 
                     "   valias_delete failed - %s\n", 
                     mysql_error( &mysql_update ));
            last_query = SqlBufUpdate;
            verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
            fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
            if( showerrors )  {
                vsqlerror( stderr, "valias delete" );
            }
            return( verrori );
        }
    }
    return(0);
}

/************************************************************************
 *
 *  valias_delete_domain
 */

int valias_delete_domain( char *domain)
{

#ifdef SHOW_TRACE
    fprintf( stderr, "valias_delete_domain( domain: %s )\n", domain );
#endif

    if (vauth_open_update()) return (verrori);

    qnprintf( SqlBufUpdate, SQL_BUF_SIZE, 
        "delete from valias where domain = '%s'", 
        domain );

#ifdef SHOW_QUERY
    fprintf( stderr, "valias_delete_domain query\n%s\n", SqlBufUpdate );
#endif
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        vcreate_valias_table();
#ifdef SHOW_QUERY
        fprintf( stderr, "valias_delete_domain retry\n%s\n", SqlBufUpdate );
#endif
        if (mysql_query(&mysql_update,SqlBufUpdate)) {
            snprintf(sqlerr, MAX_BUFF, 
                     "   valias_delete_domain failed %s - %s\n", 
                     domain, mysql_error( &mysql_update ));
            last_query = SqlBufUpdate;
            verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
            fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
            if( showerrors )  {
                vsqlerror( stderr, "valias delete domain" );
            }
            return( verrori );
        }
    }
    return(0);
}

/************************************************************************
 *
 *  vcreate_valias_table
 */

void vcreate_valias_table()
{
  vauth_create_table ("valias", VALIAS_TABLE_LAYOUT);
}

char *valias_select_all( char *alias, char *domain )
{
 struct linklist *temp_entry = NULL;
#ifdef SHOW_TRACE
    fprintf( stderr, "valias_select_all( alias: %s domain: %s )\n", 
             alias, domain );
#endif

    /* remove old entries as necessary */
    while (valias_current != NULL)
        valias_current = linklist_del (valias_current);

    if ( vauth_open_read() ) return(NULL);

    qnprintf( SqlBufRead, SQL_BUF_SIZE, 
        "select alias, valias_line from valias where domain = '%s' order by alias", domain );

#ifdef SHOW_QUERY
    fprintf( stderr, "vcreate_valias_table query\n%s\n", SqlBufRead );
#endif
    if (mysql_query(&mysql_read,SqlBufRead)) {
        vcreate_valias_table();
#ifdef SHOW_QUERY
        fprintf( stderr, "vcreate_valias_table retry\n%s\n", SqlBufRead );
#endif
        if (mysql_query(&mysql_read,SqlBufRead)) {
            snprintf(sqlerr, MAX_BUFF, 
                     "   valias_select_all failed - %s\n", 
                     mysql_error( &mysql_update ));
            last_query = SqlBufRead;
            verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
            fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
            if( showerrors )  {
                vsqlerror( stderr, "create alias table query" );
            }
            return(NULL);
        }
    }
    if(!( res_read = mysql_store_result(&mysql_read))) {
        snprintf(sqlerr, MAX_BUFF, 
                 "   vcreate_alias_table - %s\n", 
                 mysql_error( &mysql_update ));
        last_query = SqlBufRead;
        verrori = VA_STORE_RESULT_FAILED;

#ifdef SHOW_TRACE
        fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
        if( showerrors )  {
            vsqlerror( stderr, "create alias table read" );
        }
        return(NULL);
    }

    while ((row = mysql_fetch_row(res_read))) {
        temp_entry = linklist_add (temp_entry, row[1], row[0]);
        if (valias_current == NULL) valias_current = temp_entry;
    }
    mysql_free_result (res_read);

    if (valias_current == NULL) return NULL; /* no results */
    else {
        strcpy (alias, valias_current->d2);
        return(valias_current->data);
    }
}

/************************************************************************
 *
 *  valias_select_all_next
 */

char *valias_select_all_next(char *alias)
{
#ifdef SHOW_TRACE
    fprintf( stderr, "valias_select_all_next( alias: %s )\n", alias );
#endif
    if (valias_current == NULL) return NULL;
    valias_current = linklist_del (valias_current);
     
    if (valias_current == NULL) return NULL; /* no results */
    else {
        strcpy (alias, valias_current->d2);
#ifdef DUMP_DATA
        fprintf(stderr, "   alias: %s something: %s\n", alias, valias_current->data );
#endif
        return(valias_current->data);
    }
}

/************************************************************************
 *
 *  valias_select_names
 */

char *valias_select_names( char *alias, char *domain )
{
 struct linklist *temp_entry = NULL;

#ifdef SHOW_TRACE
    fprintf( stderr, "valias_select_names( alias: %s domain: %s )\n",
             alias, domain );
#endif      

    /* remove old entries as necessary */
    while (valias_current != NULL)
        valias_current = linklist_del (valias_current);

    if ( vauth_open_read() ) return(NULL);

    qnprintf( SqlBufRead, SQL_BUF_SIZE, 
        "select distinct alias from valias where domain = '%s' order by alias", domain );

#ifdef SHOW_QUERY
    fprintf( stderr, "valias_select_names query\n%s\n", SqlBufRead );
#endif
    if (mysql_query(&mysql_read,SqlBufRead)) {
        vcreate_valias_table();
#ifdef SHOW_QUERY
        fprintf( stderr, "valias_select_names retry\n%s\n", SqlBufRead );
#endif
        if (mysql_query(&mysql_read,SqlBufRead)) {
            snprintf(sqlerr, MAX_BUFF, 
                     "   valias_select_names failed - %s\n", 
                     mysql_error( &mysql_update ));
            last_query = SqlBufRead;
            verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
            fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
            if( showerrors )  {
                vsqlerror( stderr, "select names query" );
            }
            return(NULL);
        }
    }
    if(!( res_read = mysql_store_result(&mysql_read))) {
        snprintf(sqlerr, MAX_BUFF, 
                 "   valias_select_names - %s\n", 
                 mysql_error( &mysql_update ));
        last_query = SqlBufRead;
        verrori = VA_STORE_RESULT_FAILED;

#ifdef SHOW_TRACE
        fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
        if( showerrors )  {
            vsqlerror( stderr, "select names read" );
        }
        return(NULL);
    }

    while ((row = mysql_fetch_row(res_read))) {
        temp_entry = linklist_add (temp_entry, row[1], row[0]);
        if (valias_current == NULL) valias_current = temp_entry;
    }
    mysql_free_result (res_read);
 
    if (valias_current == NULL) return NULL; /* no results */
    else {
        strcpy (alias, valias_current->d2);
        return(valias_current->data);
    }
}

/************************************************************************
 *
 *  valias_select_names_next
 */

char *valias_select_names_next(char *alias)
{
#ifdef SHOW_TRACE
    fprintf( stderr, "valias_select_names_next( alias: %s )\n", alias );
#endif
    if (valias_current == NULL) return NULL;
    valias_current = linklist_del (valias_current);
 
    if (valias_current == NULL) return NULL; /* no results */
    else {
        strcpy (alias, valias_current->d2);
#ifdef DUMP_DATA
        fprintf(stderr, "   alias: %s something: %s\n", alias, valias_current->data );
#endif
        return(valias_current->data);
    }
}


/************************************************************************
 *
 *  valias_select_names_end
 */

void valias_select_names_end() {

//  not needed by mysql

}

#endif

/************************************************************************
 *
 *  logmysql
 */

#ifdef ENABLE_MYSQL_LOGGING
int logmysql(int verror, char *TheUser, char *TheDomain, char *ThePass, 
  char *TheName, char *IpAddr, char *LogLine) 
{
 time_t mytime;
 
#ifdef SHOW_TRACE
    fprintf( stderr, "logmysql( verror: %i user: %s domain: %s " 
                     "password %s name: %s ip: %s log %s )\n",
                     verror, TheUser, TheDomain, ThePass, TheName,
                     IpAddr, LogLine );
#endif


    mytime = time(NULL);
    if (vauth_open_update()) return (verrori);

    qnprintf( SqlBufUpdate, SQL_BUF_SIZE,
        "INSERT INTO vlog set user='%s', passwd='%s', \
        domain='%s', logon='%s', remoteip='%s', message='%s', \
        error=%i, timestamp=%d", TheUser, ThePass, TheDomain,
        TheName, IpAddr, LogLine, verror, (int)mytime);

#ifdef SHOW_QUERY
    fprintf( stderr, "logmysql query\n%s\n", SqlBufUpdate );
#endif
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        vcreate_vlog_table();
#ifdef SHOW_QUERY
        fprintf( stderr, "logmysql retry\n%s\n", SqlBufUpdate );
#endif
        if (mysql_query(&mysql_update,SqlBufUpdate)) {
            snprintf(sqlerr, MAX_BUFF, 
                     "   logmysql failed - %s\n", 
                     mysql_error( &mysql_update ));
            last_query = SqlBufUpdate;
            verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
            fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
            if( showerrors )  {
                vsqlerror( stderr, "Log mysql" );
            }
            return( verrori );
        }
    }
    return(0);
}


/************************************************************************
 *
 *  vcreate_vlog_table
 */

void vcreate_vlog_table()
{
  vauth_create_table ("vlog", VLOG_TABLE_LAYOUT);
}
#endif

/************************************************************************
 *
 *  vcreat_limits_table
 */

#ifdef ENABLE_MYSQL_LIMITS
void vcreate_limits_table()
{
  vauth_create_table ("limits", LIMITS_TABLE_LAYOUT);
}

/************************************************************************
 *
 *  vget_limits
 */

int vget_limits(const char *domain, struct vlimits *limits)
{
#ifdef SHOW_TRACE
    fprintf( stderr, "vget_limits( domain: %s )\n", domain );
#endif

    vdefault_limits (limits);

    if ( vauth_open_read() ) return(verrori);

    qnprintf(SqlBufRead, SQL_BUF_SIZE, "SELECT maxpopaccounts, maxaliases, "
        "maxforwards, maxautoresponders, maxmailinglists, diskquota, "
        "maxmsgcount, defaultquota, defaultmaxmsgcount, "
        "disable_pop, disable_imap, disable_dialup, "
        "disable_passwordchanging, disable_webmail, disable_relay, "
        "disable_smtp, perm_account, perm_alias, perm_forward, "
        "perm_autoresponder, perm_maillist, perm_quota, perm_defaultquota \n"
        "FROM limits \n"
        "WHERE domain = '%s'", domain);


#ifdef SHOW_QUERY
    fprintf( stderr, "vget_limits query\n%s\n", SqlBufRead );
#endif
    if (mysql_query(&mysql_read,SqlBufRead)) {
        vcreate_limits_table();
#ifdef SHOW_QUERY
        fprintf( stderr, "vget_limits retry\n%s\n", SqlBufRead );
#endif
        if (mysql_query(&mysql_read,SqlBufRead)) {
            snprintf(sqlerr, MAX_BUFF, 
                     "   vget_limits %s failed - %s\n", 
                     domain, mysql_error( &mysql_update ));
            last_query = SqlBufRead;
            verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
            fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
            if( showerrors )  {
                vsqlerror( stderr, "vget limits query" );
            }
            return( verrori );
        }
    }

    if (!(res_read = mysql_store_result(&mysql_read))) {
        snprintf(sqlerr, MAX_BUFF, 
                 "   vget_limits - %s\n", 
                 mysql_error( &mysql_update ));
        last_query = SqlBufRead;
        verrori = VA_STORE_RESULT_FAILED;

#ifdef SHOW_TRACE
        fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
        if( showerrors )  {
            vsqlerror( stderr, "fget limits read" );
        }
        return(verrori);
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

#ifdef DUMP_DATA 
    fprintf( stderr, 
        "   Max:\n"
        "      pop: %i  alias: %i  forward: %i auto: %i list: %i\n"
        "   Quota:\n"
        "      disk: %i default: %i msgcount: %i\n"
        "   Disable:\n"
        "      pop: %i imap: %i dialup: %i  pw change: %i "
        "webmail: %i relay: %i smtp: %i\n"
        "   Perm:\n"
        "      account: %i alias: %i forward: %i auto: %i "
        "maillist: %i users: %i moderate: %i quota: %i def quota: %i\n\n",
        limits->maxpopaccounts, limits->maxaliases, limits->maxforwards,
        limits->maxautoresponders, limits->maxmailinglists, 

        limits->diskquota, limits->defaultquota, 
        limits->defaultmaxmsgcount,

        limits->disable_pop, limits->disable_imap,
        limits->disable_dialup, limits->disable_passwordchanging,
        limits->disable_webmail, limits->disable_relay,
        limits->disable_smtp,

        limits->perm_account, limits->perm_alias,
        limits->perm_forward, limits->perm_autoresponder,
        limits->perm_maillist, limits->perm_maillist_users,
        limits->perm_maillist_moderators, limits->perm_quota,
        limits->perm_defaultquota);
#endif

    return 0;
}

/************************************************************************
 *
 *  vset_limits
 */

int vset_limits(const char *domain, const struct vlimits *limits)
{
    if (vauth_open_update()) return (verrori);

    qnprintf(SqlBufUpdate, SQL_BUF_SIZE, "REPLACE INTO limits ("
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

#ifdef SHOW_QUERY
    fprintf( stderr, "vset_limits query\n%s\n", SqlBufUpdate );
#endif
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        vcreate_limits_table();
#ifdef SHOW_QUERY
        fprintf( stderr, "vset_limits retry\n%s\n", SqlBufUpdate );
#endif
        if (mysql_query(&mysql_update,SqlBufUpdate)) {
            snprintf(sqlerr, MAX_BUFF, 
                     "   vset_limits failed - %s\n", 
                     mysql_error( &mysql_update ));
            last_query = SqlBufUpdate;
            verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
            fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
            if( showerrors )  {
                vsqlerror( stderr, "vset limits" );
            }
            return( verrori );
        }
    }

    return 0;
}

/************************************************************************
 *
 *  vdel_limits
 */

int vdel_limits(const char *domain)
{
#ifdef SHOW_TRACE
    fprintf( stderr, "vdel_limits( domain: %s )\n", domain );
#endif

    qnprintf(SqlBufUpdate, SQL_BUF_SIZE, "DELETE FROM limits WHERE domain = '%s'", domain);

#ifdef SHOW_QUERY
    fprintf( stderr, "vdel_limits query\n%s\n", SqlBufUpdate );
#endif
    if (mysql_query(&mysql_update,SqlBufUpdate)) {
        snprintf(sqlerr, MAX_BUFF, 
                 "   vdel_limits failed - %s\n", 
                 mysql_error( &mysql_update ));
        last_query = SqlBufUpdate;
        verrori = VA_QUERY_FAILED;

#ifdef SHOW_TRACE
        fprintf(stderr, "%s\n%s\n", sqlerr, last_query );
#endif
        if( showerrors )  {
            vsqlerror( stderr, "vdel limits" );
        }
        return( verrori );
    }

    return 0;
}

#endif

/************************************************************************
 *
 *  vauth_crypt
 */

int vauth_crypt(char *user,char *domain,char *clear_pass,struct vqpasswd *vpw)
{
  if ( vpw == NULL ) return(-1);

  return(strcmp(crypt(clear_pass,vpw->pw_passwd),vpw->pw_passwd));
}
