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
#include <pwd.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <libpq-fe.h> /* required pgsql front-end headers */

#include "config.h"
#include "vpopmail.h"
#include "vauth.h"
#include "vlimits.h"
#include "vpgsql.h"

/* pgsql has no built-in replication, yet.
   #ifdef PGSQL_REPLICATION
   static PGconn *pgc_read;
   #else
   #define pgc_read pgc_update
   #endif

   #ifdef PGSQL_REPLICATION
   static int read_open = 0;
   #else
   #define read_open update_open
   #endif
   #ifdef PGSQL_REPLICATION	
   static PGresult *res_read = NULL;
   #else
   #define res_read res_update
   #endif
*/

/* 
   read-only and read-write connections 
   to be implemented later...
static PGconn *pgc_update;
static PGconn *pgc_read;
static PGconn *pgc_read_getall;
*/

static PGconn *pgc; /* pointer to pgsql connection */
static int is_open = 0;

#define SQL_BUF_SIZE 600
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
void vpgsql_escape( char *instr, char *outstr );

#ifdef POP_AUTH_OPEN_RELAY
void vcreate_relay_table();
#endif

#ifdef VALIAS
void vcreate_valias_table();
#endif

#ifdef ENABLE_AUTH_LOGGING
void vcreate_lastauth_table();
#endif

/* pgsql BEGIN TRANSACTION ********/
int pg_begin(void)
{
  PGresult *pgres;
  pgres=PQexec(pgc, "BEGIN");
  if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    fprintf(stderr, "pg_begin: %s\n", PQresultErrorMessage(pgres));
    return -1;
  }
  PQclear(pgres);
  return 0;
}                                       

/* pgsql END TRANSACTION ********/
int pg_end(void)
{
  PGresult *pgres;
  pgres=PQexec(pgc, "END");
  if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    fprintf(stderr, "pg_end: %s\n", PQresultErrorMessage(pgres));
    return -1;
  }
  PQclear(pgres);
  return 0;
}                                                   
/*** Open a connection to pgsql ***/
int vauth_open()
{
  if ( is_open != 0 ) return(0);
  is_open = 1;
  verrori = 0;

  /* Try to connect to the pgserver with the specified database. */
  pgc = PQconnectdb(PG_CONNECT);
  if( PQstatus(pgc) == CONNECTION_BAD) {
    fprintf(stderr, "vauth_open: can't connect: %s\n", PQerrorMessage(pgc));
    return VA_NO_AUTH_CONNECTION;
  }	
  return(0);
}

int vauth_adddomain( char *domain )
{
  char *tmpstr = NULL;
  int err;
  PGresult *pgres;
    
  if ( (err=vauth_open()) != 0 ) return(err);

  vset_default_domain( domain );
#ifndef MANY_DOMAINS
  tmpstr = vauth_munch_domain( domain );
#else
  tmpstr = PGSQL_DEFAULT_TABLE;
#endif
  snprintf(SqlBufUpdate,SQL_BUF_SIZE, 
	   "create table %s ( %s )",tmpstr,TABLE_LAYOUT);

  pgres = PQexec(pgc, SqlBufUpdate);
  if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
#ifndef MANY_DOMAINS
    fprintf(stderr, "vauth_adddomain : create table failed : %s\n",
	    PQresultErrorMessage(pgres));
    return(-1);
#endif
  }
  if(pgres) PQclear(pgres);
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
  PGresult *pgres;
    
  if ( (err=vauth_open()) != 0 ) return(err);
  vset_default_domain( domain );

#ifdef HARD_QUOTA
  snprintf( quota, 30, "%s", HARD_QUOTA );
#else
  strncpy( quota, "NOQUOTA", 30 );
#endif

#ifndef MANY_DOMAINS
  domstr = vauth_munch_domain( domain );
#else
  domstr = PGSQL_DEFAULT_TABLE;
#endif
  if ( domain == NULL || domain[0] == 0 ) {
    domstr = PGSQL_LARGE_USERS_TABLE;
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
      snprintf(dirbuf,SQL_BUF_SIZE, "%s/%s", dom_dir, user);
    }
  }

  if ( pass[0] != 0 ) {
    mkpasswd3(pass,Crypted, 100);
  } else {
    Crypted[0] = 0;
  }
  vpgsql_escape( Crypted, EPass );
  vpgsql_escape( gecos, EGecos );
#ifdef CLEAR_PASS
  vpgsql_escape( pass, EClearPass);
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
  if(! ( pgres=PQexec(pgc,SqlBufUpdate) )||
     PQresultStatus(pgres)!=PGRES_COMMAND_OK )  {
    fprintf(stderr, "vauth_adduser: %s\npgsql: %s\n", 
	    SqlBufUpdate, PQresultErrorMessage(pgres));
  }
  if( pgres )  PQclear(pgres);
  return(0);

}
struct vqpasswd *vauth_getpw(char *user, char *domain)
{
  char *in_domain;
  char *domstr;
  int mem_size;
  static struct vqpasswd vpw;
  int err;
  PGresult *pgres;
  struct vlimits limits;

  verrori = 0;
  if ( (err=vauth_open()) != 0 ) {
    verrori = err;
    return(NULL);
  }
  lowerit(user);
  lowerit(domain);

  mem_size = 100; 
  in_domain = calloc(mem_size, sizeof(char));
  strncpy(in_domain, domain, mem_size);

  vset_default_domain( in_domain );

#ifndef MANY_DOMAINS
  domstr = vauth_munch_domain( in_domain );
#else
  domstr = PGSQL_DEFAULT_TABLE; 
#endif

  if ( domstr == NULL || domstr[0] == 0 ) {
    domstr = PGSQL_LARGE_USERS_TABLE;
  }

  snprintf(SqlBufRead, SQL_BUF_SIZE, USER_SELECT, domstr, user
#ifdef MANY_DOMAINS
	   ,in_domain
#endif	
	   );
  if( in_domain ) free(in_domain);
  pgres=PQexec(pgc, SqlBufRead);
  if ( ! pgres || PQresultStatus(pgres)!=PGRES_TUPLES_OK) {
    if( pgres ) PQclear(pgres);	
    fprintf(stderr, 
	    "vauth_getpw: failed select: %s : %s\n", 
	    SqlBufRead, PQresultErrorMessage(pgres));
    return NULL;
  }
  if ( PQntuples(pgres) <= 0 ) { /* rows count */
    PQclear(pgres);
    return NULL;
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

  strncpy(vpw.pw_name,PQgetvalue( pgres, 0, 0 ),SMALL_BUFF);
  strncpy(vpw.pw_passwd,PQgetvalue( pgres, 0, 1 ),SMALL_BUFF);
  vpw.pw_uid    = atoi(PQgetvalue( pgres, 0, 2 ));
  vpw.pw_gid    = atoi(PQgetvalue( pgres, 0, 3 ));
  strncpy(vpw.pw_gecos,PQgetvalue( pgres, 0, 4 ),SMALL_BUFF);
  strncpy(vpw.pw_dir,PQgetvalue( pgres, 0, 5 ),SMALL_BUFF);
  strncpy(vpw.pw_shell, PQgetvalue( pgres, 0, 6 ),SMALL_BUFF);
#ifdef CLEAR_PASS
  if ( PQgetvalue( pgres, 0, 7 ) != 0 )
    strncpy(vpw.pw_clear_passwd, PQgetvalue( pgres, 0, 7 ),SMALL_BUFF);
#endif

  if ((! pwent.pw_gid && V_OVERRIDE)
    && (vget_limits (in_domain, &limits) == 0) {
      pwent.pw_flags = pwent.pw_gid | vlimits_get_gid_mask (&limits);
  } else pwent.pw_flags = pwent.pw_gid;

  return(&vpw);
}

int vauth_deldomain( char *domain )
{
  PGresult *pgres;
  char *tmpstr;
  int err;
    
  if ( (err=vauth_open()) != 0 ) return(err);
  vset_default_domain( domain );

#ifndef MANY_DOMAINS
  tmpstr = vauth_munch_domain( domain );
  snprintf( SqlBufUpdate, SQL_BUF_SIZE, "drop table %s", tmpstr);
#else
  tmpstr = PGSQL_DEFAULT_TABLE;
  snprintf(SqlBufUpdate,SQL_BUF_SIZE,
	   "delete from %s where pw_domain = '%s'",
	   tmpstr, domain );
#endif 
  pgres=PQexec(pgc, SqlBufUpdate);
  if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK){
    fprintf(stderr,"vauth_deldomain: pgsql query: %s",
	    PQresultErrorMessage(pgres));
    return(-1);
  } 
  if(pgres) PQclear(pgres);

#ifdef VALIAS 
    valias_delete_domain( domain);
#endif

#ifdef ENABLE_AUTH_LOGGING
    snprintf( SqlBufUpdate, SQL_BUF_SIZE, 
        "delete from lastauth where domain = '%s'", domain );
    pgres=PQexec(pgc, SqlBufUpdate);
    if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK) {
      return(-1);
    } 	
    if(pgres) PQclear(pgres);
#endif
    return(0);
}

int vauth_deluser( char *user, char *domain )
{
  PGresult *pgres;
  char *tmpstr;
  int err = 0;
    
  if ( (err=vauth_open()) != 0 ) return(err);
  vset_default_domain( domain );

#ifndef MANY_DOMAINS
  if ( domain == NULL || domain[0] == 0 ) {
    tmpstr = PGSQL_LARGE_USERS_TABLE;
  } else {
    tmpstr = vauth_munch_domain( domain );
  }
#else
  tmpstr = PGSQL_DEFAULT_TABLE;
#endif

  snprintf( SqlBufUpdate, SQL_BUF_SIZE, DELETE_USER, tmpstr, user
#ifdef MANY_DOMAINS
	    , domain
#endif
	    );

  pgres=PQexec(pgc, SqlBufUpdate);
  if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    err = -1;
  } 
  if( pgres ) PQclear(pgres);

#ifdef ENABLE_AUTH_LOGGING
  snprintf( SqlBufUpdate, SQL_BUF_SIZE, 
	    "delete from lastauth where user = '%s' and domain = '%s'", 
	    user, domain );
  pgres=PQexec(pgc, SqlBufUpdate);
  if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    err = -1;
  }
  if( pgres ) PQclear(pgres);
#endif
  return(err);
}

int vauth_setquota( char *username, char *domain, char *quota)
{
  PGresult *pgres;
  char *tmpstr;
  int err;

  if ( strlen(username) > MAX_PW_NAME ) return(VA_USER_NAME_TOO_LONG);
#ifdef USERS_BIG_DIR
  if ( strlen(username) == 1 ) return(VA_ILLEGAL_USERNAME);
#endif
  if ( strlen(domain) > MAX_PW_DOMAIN ) return(VA_DOMAIN_NAME_TOO_LONG);
  if ( strlen(quota) > MAX_PW_QUOTA )    return(VA_QUOTA_TOO_LONG);
    
  if ( (err=vauth_open()) != 0 ) return(err);
  vset_default_domain( domain );

#ifndef MANY_DOMAINS
  tmpstr = vauth_munch_domain( domain );
#else
  tmpstr = PGSQL_DEFAULT_TABLE; 
#endif

  snprintf( SqlBufUpdate, SQL_BUF_SIZE, SETQUOTA, tmpstr, quota, username
#ifdef MANY_DOMAINS
	    , domain
#endif		
	    );

  pgres = PQexec(pgc, SqlBufUpdate);
  if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    fprintf(stderr, 
	    "vauth_setquota: query failed: %s\n", PQresultErrorMessage(pgres));
    return(-1);
  } 
  if( pgres ) PQclear(pgres);
  return(0);
}

struct vqpasswd *vauth_getall(char *domain, int first, int sortit)
{
  static PGresult *pgres=NULL; 
  /* ntuples - number of tuples ctuple - current tuple */
  static unsigned ntuples=0, ctuple=0;      

  char *domstr = NULL;
  static struct vqpasswd vpw;
  int err;

  vset_default_domain( domain );

#ifdef MANY_DOMAINS
  domstr = PGSQL_DEFAULT_TABLE; 
#else
  domstr = vauth_munch_domain( domain );
#endif

  if ( first == 1 ) {
    if ( (err=vauth_open()) != 0 ) return(NULL);
    snprintf(SqlBufRead,  SQL_BUF_SIZE, GETALL, domstr
#ifdef MANY_DOMAINS
	     ,domain
#endif
	     );
    if ( sortit == 1 ) {
      strncat( SqlBufRead, " order by pw_name", SQL_BUF_SIZE);
    }
    if ( pgres ) { /* reset state if we had previous result */
      PQclear(pgres);    // clear previous result	
      ntuples=ctuple=0;	
    }	
    pgres = PQexec(pgc, SqlBufRead);
    if( !pgres || PQresultStatus(pgres) != PGRES_TUPLES_OK ) {
      if( pgres ) PQclear(pgres);
      printf("vauth_getall:query failed[5]: %s\n",PQresultErrorMessage(pgres));
      return (NULL);
    }
    ntuples = PQntuples( pgres );
  }

  if ( ctuple == ntuples ) {
    PQclear(pgres);
    ctuple=ntuples=0;
    return NULL;
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
    
  strncpy(vpw.pw_name, PQgetvalue( pgres, 0, 0 ),SMALL_BUFF );
  strncpy(vpw.pw_passwd, PQgetvalue( pgres, 0, 1 ),SMALL_BUFF );

  vpw.pw_uid    = atoi(PQgetvalue( pgres, 0, 2 ));
  vpw.pw_gid    = atoi(PQgetvalue( pgres, 0, 3 ));

  strncpy(vpw.pw_gecos, PQgetvalue( pgres, 0, 4 ),SMALL_BUFF);
  strncpy(vpw.pw_dir, PQgetvalue( pgres, 0, 5 ),SMALL_BUFF);
  strncpy(vpw.pw_shell, PQgetvalue( pgres, 0, 6 ),SMALL_BUFF);

#ifdef CLEAR_PASS
    if (PQgetvalue( pgres, 0, 7 )!= 0 ) {
      strncpy(vpw.pw_clear_passwd, PQgetvalue( pgres, 0, 7 ),SMALL_BUFF);
    }
#endif
    ctuple++;
    return(&vpw);
}

void vauth_end_getall()
{
  /* not applicable in pgsql? */
}

char *vauth_munch_domain( char *domain )
{
  int i;
  static char tmpbuf[50];

  if ( domain == NULL || domain[0] == 0 ) return(domain);

  for(i=0;domain[i]!=0;++i){
    tmpbuf[i] = domain[i];
    if ( domain[i] == '.' || domain[i] == '-' ) {
      tmpbuf[i] = SQL_DOT_CHAR;
    }
  }
  tmpbuf[i] = 0; 
  return(tmpbuf);
}

int vauth_setpw( struct vqpasswd *inpw, char *domain )
{
  PGresult *pgres;
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

  if ( (err=vauth_open()) != 0 ) return(err);
  vset_default_domain( domain );

#ifndef MANY_DOMAINS
  tmpstr = vauth_munch_domain( domain );
#else
  tmpstr = PGSQL_DEFAULT_TABLE; 
#endif

  vpgsql_escape( inpw->pw_passwd, EPass );
  vpgsql_escape( inpw->pw_gecos, EGecos );
#ifdef CLEAR_PASS
  vpgsql_escape( inpw->pw_clear_passwd, EClearPass );
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
  pgres=PQexec(pgc, SqlBufUpdate);
  if ( !pgres || PQresultStatus(pgres)!= PGRES_COMMAND_OK ) {
    fprintf(stderr, "vauth_setpw: pgsql query[6]: %s\n", 
	    PQresultErrorMessage(pgres));
    if( pgres )  PQclear(pgres);
    return(-1);
  } 
  if( pgres ) PQclear(pgres);
#ifdef SQWEBMAIL_PASS
    vsqwebmail_pass( inpw->pw_dir, inpw->pw_passwd, uid, gid);
#endif
    return(0);
}

#ifdef POP_AUTH_OPEN_RELAY
int vopen_smtp_relay()
{
  PGresult *pgres;
  char *ipaddr;
  time_t mytime;
  int err;

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

  if ( (err=vauth_open()) != 0 ) return 0;

  snprintf(SqlBufUpdate, SQL_BUF_SIZE, 
    "UPDATE relay SET ip_addr='%s', timestamp=%d WHERE ip_addr='%s'",
    ipaddr, (int)mytime, ipaddr);

  pgres=PQexec(pgc, SqlBufUpdate);
  if (PQresultStatus(pgres) == PGRES_COMMAND_OK && atoi(PQcmdTuples(pgres)) == 0) {
    if( pgres ) PQclear(pgres);

    snprintf( SqlBufUpdate, SQL_BUF_SIZE,
      "INSERT INTO relay (ip_addr, timestamp) VALUES ('%s', %lu)",
      ipaddr, time(NULL)); 

    pgres=PQexec(pgc, SqlBufUpdate);
    }

/* UPDATE returned 0 rows and/or INSERT failed.  Try creating the table */
  if(!pgres || PQresultStatus(pgres) != PGRES_COMMAND_OK) {
    if( pgres ) PQclear(pgres);

    vcreate_relay_table();

/* and try INSERTing now... */
    snprintf( SqlBufUpdate, SQL_BUF_SIZE,
      "INSERT INTO relay (ip_addr, timestamp) VALUES ('%s', %lu)",
      ipaddr, time(NULL)); 

    pgres=PQexec(pgc, SqlBufUpdate);
    }

  if(!pgres || PQresultStatus(pgres)!= PGRES_COMMAND_OK ) {
    /* need to return non-zero value if value inserted */
    if( pgres ) PQclear(pgres);
    return 1;
  }

  if( pgres ) PQclear(pgres);
  return 0;
}

void vupdate_rules(int fdm)
{
  PGresult *pgres;
  const char re[]=":allow,RELAYCLIENT=\"\",RBLSMTPD=\"\"\n";
  register unsigned i=0, n, len=strlen(re)+1;
  char *buf=NULL;

  if (vauth_open() != 0) return;

  snprintf(SqlBufRead, SQL_BUF_SIZE, "SELECT ip_addr FROM relay");
  if ( !(pgres=PQexec(pgc, SqlBufRead)) || PQresultStatus(pgres)!=PGRES_TUPLES_OK) {
    vcreate_relay_table();
    if(pgres) PQclear(pgres);
    if ( !(pgres=PQexec(pgc, SqlBufRead)) || PQresultStatus(pgres)!=PGRES_TUPLES_OK ) {
      printf("vupdate_rules: query : %s\n", PQresultErrorMessage(pgres));
      return;
    }
  }
  
  n=PQntuples(pgres);
  for( ; i < n ; i++ ) {
    buf=realloc(buf, len+PQgetlength(pgres, i, 0) );
    if( buf==NULL || errno==ENOMEM ) {
      PQclear(pgres);
      free(buf);
      fprintf(stderr, "vupdate_rules: no mem\n");
      return;
    }

    sprintf( buf, "%s%s", PQgetvalue(pgres, i, 0), re );
    if( write( fdm, buf, strlen(buf) ) != strlen(buf) ) {
      fprintf(stderr, "vupdate_rules: short write: %s",
	      strerror(errno));
      break;
    }
  }
  if(pgres) PQclear(pgres);
  free(buf);
  return;
}

void vclear_open_smtp(time_t clear_minutes, time_t mytime)
{
  PGresult *pgres;
  time_t delete_time;
  int err;
    
  if ( (err=vauth_open()) != 0 ) return;
  delete_time = mytime - clear_minutes;

  snprintf( SqlBufUpdate, SQL_BUF_SIZE, 
	    "DELETE FROM relay WHERE timestamp <= %d", 
	    (int)delete_time);
  pgres=PQexec(pgc, SqlBufUpdate);
  free(SqlBufUpdate);
  if( !pgres || PQresultStatus(pgres) != PGRES_COMMAND_OK) {
    vcreate_relay_table();
  }
  return;
}

void vcreate_relay_table()
{
  PGresult *pgres;
  if (vauth_open() != 0) return;
  snprintf( SqlBufCreate, SQL_BUF_SIZE, 
	    "CREATE TABLE relay ( %s )", RELAY_TABLE_LAYOUT);
  pgres=PQexec(pgc, SqlBufCreate);
  free(SqlBufCreate);
  if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK) {
    fprintf(stderr, "vcreate_relay_table: create failed[9]: %s \n", 
	    PQresultErrorMessage(pgres));
  }
  if(pgres) PQclear(pgres);
  return;
}
#endif

int vmkpasswd( char *domain )
{
    return(0);
}

void vclose()
{
  /* disconnection from the database */
  if ( is_open == 1 ) {
    is_open = 0;
    PQfinish(pgc);
  }
}

#ifdef IP_ALIAS_DOMAINS
void vcreate_ip_map_table()
{
  PGresult *pgres;
  if ( vauth_open() != 0 ) return;

  snprintf(SqlBufCreate, SQL_BUF_SIZE, "create table ip_alias_map ( %s )", 
      IP_ALIAS_TABLE_LAYOUT);
  pgres=PQexec(pgc, SqlBufCreate);
  free(SqlBufCreate);
  if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK)
    fprintf(stderr,"vcreate_ip_map_table[a]:%s\n",PQresultErrorMessage(pgres));
  if( pgres ) PQclear(pgres);
  return;
}

int vget_ip_map( char *ip, char *domain, int domain_size)
{
  PGresult *pgres;
  char *ptr;
  unsigned ntuples;
  int ret = -1;

  if ( ip == NULL || strlen(ip) <= 0 ) return(-1);
  if ( domain == NULL ) return(-2);
  if ( vauth_open_read() != 0 ) return(-3);

  snprintf(SqlBufRead, SQL_BUF_SIZE,
	   "select domain from ip_alias_map where ip_addr = '%s'",
	   ip);
  pgres=PQexec(pgc, SqlBufRead);
  free(SqlBufRead);
  if( !pgres || PQresultStatus(pgres) != PGRES_TUPLES_OK ) {
    fprintf( stderr, "vget_ip_map: pgsql query: %s\n", PQerrorMessage(pgc));
      if( pgres ) PQclear(pgres);
      return -1;
    }

  ntuples = PQntuples(pgres);
  if(!ntuples)
    *domain='\0';
  else {
    ret = 0;
    ptr = PQgetvalue(pgres, ntuples-1, 0);
    strncpy(domain, ptr, strlen(ptr) );
  }

  PQclear(pgres);
  return (ret);
}

int vadd_ip_map( char *ip, char *domain) 
{
  PGresult *pgres;
  int err = 0;
  
  if ( ip == NULL || strlen(ip) <= 0 ) return(-1);
  if ( domain == NULL || strlen(domain) <= 0 ) return(-1);

  if ( (err=vauth_open()) != 0 ) return(err);

  if( ( err=pg_begin() )!= 0 ) {     /* begin transaction */
    free(SqlBufUpdate);
    return(err);
  }
  snprintf(SqlBufUpdate,SQL_BUF_SIZE,  
	   "delete from ip_alias_map where ip_addr='%s' and domain='%'",
	   ip, domain);

  /* step 1: delete previous entry */
  pgres=PQexec(pgc, SqlBufUpdate);
  if( pgres ) PQclear(pgres); /* don't check pgres status 
				 table may not exist */

  /* step 2: insert new data */
  snprintf(SqlBufUpdate,SQL_BUF_SIZE,  
	   "insert into ip_alias_map (ip_addr,domain) values ('%s','%s')",
	   ip, domain);
  pgres=PQexec(pgc, SqlBufUpdate);
  if ( !pgres || PQresultStatus(pgres) != PGRES_COMMAND_OK ) {
    if( pgres ) PQclear(pgres);
    vcreate_ip_map_table();
    snprintf(SqlBufUpdate,SQL_BUF_SIZE,  
	   "insert into ip_alias_map (ip_addr,domain) values ('%s','%s')",
	     ip, domain);
    pgres=PQexec( pgc, SqlBufUpdate);
    if ( !pgres || PQresultStatus(pgres) != PGRES_COMMAND_OK ) {
      fprintf( stderr, "vadd_ip_map: insert: %s\n", PQerrorMessage(pgc));
      if( pgres ) PQclear(pgres);
      free(SqlBufUpdate);
      return -1;
    }
    if( pgres ) PQclear(pgres);
    return ( pg_end() ); /* end transaction */
}

int vdel_ip_map( char *ip, char *domain) 
{
  PGresult *pgres;
  int err=0;

  if ( ip == NULL || strlen(ip) <= 0 ) return(-1);
  if ( domain == NULL || strlen(domain) <= 0 ) return(-1);
  if ( (err=vauth_open()) != 0 ) return(err);

  snprintf( SqlBufUpdate,SQL_BUF_SIZE,  
	    "delete from ip_alias_map where ip_addr='%s' and domain='%s'",
            ip, domain);

  pgres=PQexec(pgc, SqlBufUpdate);
  if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    fprintf(stderr, "vdel_ip_map: delete failed: %s\n", 
	    PQresultErrorMessage(pgres));
    if(pgres) PQclear(pgres);
    /* #warning why are we returning 0 when we couldn't delete?*/
    return(0);
  }
  if(pgres) PQclear(pgres);
  return(0);
}	
int vshow_ip_map( int first, char *ip, char *domain )
{
  static PGresult *pgres=NULL;
  static unsigned ntuples=0, ctuple=0;
  int err= 0;

  if ( ip == NULL ) return(-1);
  if ( domain == NULL ) return(-1);
  if ( ( err=open_read() ) != 0 ) return(err);

  if ( first == 1 ) {
    snprintf(SqlBufRead,SQL_BUF_SIZE, 
	     "select ip_addr, domain from ip_alias_map"); 
    if (pgres) { 
      PQclear(pgres);
      ntuples=ctuple=0;
    }	
    if ( ! (pgres=PQexec(pgc, qr))
         || PQresultStatus(pgres) != PGRES_TUPLES_OK ) {
      if(pgres) PQclear(pgres);
      snprintf(SqlBufRead,SQL_BUF_SIZE, 
	       "select ip_addr, domain from ip_alias_map"); 
      vcreate_ip_map_table();
      if ( ! (pgres=PQexec(pgc, qr))
	   || PQresultStatus(pgres) != PGRES_TUPLES_OK ) {
	return(0);
      }
    }
    ntuples=PQntuples(pgres);
  } 

  if ( ctuple == ntuples ) {
    PQclear(pgres);
    ntuples=ctuple=0;
    return (0);
  }

  strncpy( ip, PQgetvalue( pgres, ctuple, 0), 18);
  strncpy( domain, PQgetvalue( pgres, ctuple, 1), 156);
  strncpy( ip, PQgetvalue( pgres, ctuple, 0), 18);
  strncpy( domain, PQgetvalue( pgres, ctuple, 1), 156);

  ctuple++;
  return 1;
}
#endif

int vread_dir_control(vdir_type *vdir, char *domain, uid_t uid, gid_t gid)
{
  PGresult *pgres;
  int found = 0;

  if ( vauth_open() != 0 ) return(-1);

  snprintf(SqlBufUpdate, SQL_BUF_SIZE, 
	   "select %s from dir_control where domain = '%s'", 
	   DIR_CONTROL_SELECT, domain );

  if (!(pgres=PQexec(pgc, SqlBufUpdate)) || 
      PQresultStatus(pgres)!=PGRES_TUPLES_OK ) {
      if( pgres ) PQclear(pgres);
      vcreate_dir_control(domain);
      snprintf(SqlBufUpdate, SQL_BUF_SIZE, 
	       "select %s from dir_control where domain = '%s'", 
	       DIR_CONTROL_SELECT, domain );
      if (! (pgres=PQexec(pgc, SqlBufUpdate)) || 
	  PQresultStatus(pgres)!=PGRES_TUPLES_OK ) {
	fprintf(stderr, "vread_dir_control: q: %s\npgsql: %s", 
		SqlBufUpdate, PQresultErrorMessage(pgres));
	  return (-1);
      }
  }
  if ( PQntuples(pgres) > 0 ) {
    found = 1;
    vdir->cur_users = atol( PQgetvalue( pgres, 0, 0 ) );
    vdir->level_cur = atoi( PQgetvalue( pgres, 0, 1 ) );
    vdir->level_max = atoi( PQgetvalue( pgres, 0, 2 ) );

    vdir->level_start[0] = atoi( PQgetvalue( pgres, 0, 3 ) );
    vdir->level_start[1] = atoi( PQgetvalue( pgres, 0, 4 ) );
    vdir->level_start[2] = atoi( PQgetvalue( pgres, 0, 5 ) );

    vdir->level_end[0] = atoi( PQgetvalue( pgres, 0, 6 ) );
    vdir->level_end[1] = atoi( PQgetvalue( pgres, 0, 7 ) );
    vdir->level_end[2] = atoi( PQgetvalue( pgres, 0, 8 ) );

    vdir->level_mod[0] = atoi( PQgetvalue( pgres, 0, 9 ) );
    vdir->level_mod[1] = atoi( PQgetvalue( pgres, 0, 10 ) );
    vdir->level_mod[2] = atoi( PQgetvalue( pgres, 0, 11 ) );

    vdir->level_index[0] = atoi( PQgetvalue( pgres, 0, 12 ) );
    vdir->level_index[1] = atoi( PQgetvalue( pgres, 0, 13 ) );
    vdir->level_index[2] = atoi( PQgetvalue( pgres, 0, 14 ) );

    strncpy(vdir->the_dir, PQgetvalue( pgres, 0, 15 ) , MAX_DIR_NAME);
  }
  PQclear(pgres);
  if ( found == 0 ) {
    int i;
    vdir->cur_users = 0;
    for(i=0;i<MAX_DIR_LEVELS;++i) {
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
  PGresult *pgres;

  if ( vauth_open() != 0 ) return(-1);

  snprintf(SqlBufUpdate, SQL_BUF_SIZE, 
	   "delete from dir_control where domain='%s'", domain );
  if( pg_begin() ) { /* begin transaction */
      return -1;
  }
  pgres=PQexec(pgc, SqlBufUpdate);
  if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    fprintf(stderr, "vwrite_dir_control: delete failed: %s", 
	    PQresultErrorMessage(pgres));
    return -1;
  }
  snprintf(SqlBufUpdate, SQL_BUF_SIZE,
	   "insert into dir_control ( \
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

  pgres=PQexec(pgc, SqlBufUpdate);
  if ( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    PQclear(pgres);
    vcreate_dir_control(domain);
    if ( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
      fprintf(stderr, "vwrite_dir_control: %s\n", PQresultErrorMessage(pgres));
      return(-1);
    }
  }
  PQclear(pgres);
  return pg_end(); /* end transcation */

}

void vcreate_dir_control(char *domain)
{
  PGresult *pgres;

  if ( vauth_open() != 0 ) return;

  snprintf(SqlBufCreate, SQL_BUF_SIZE, "create table dir_control ( %s )", 
	   DIR_CONTROL_TABLE_LAYOUT);

  pgres=PQexec( pgc, SqlBufCreate );
  if( ! pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    fprintf(stderr, "vcreate_dir_control: pgsql query: %s\n", 
	    PQresultErrorMessage(pgres));
    return;
  }
  if( pgres ) PQclear(pgres);

  snprintf(SqlBufUpdate, SQL_BUF_SIZE, "insert into dir_control ( \
domain, cur_users, \
level_cur, level_max, \
level_start0, level_start1, level_start2, \
level_end0, level_end1, level_end2, \
level_mod0, level_mod1, level_mod2, \
level_index0, level_index1, level_index2, the_dir ) values ( \
\'%s\', 0, \
0, %d, \
0, 0, 0, \
%d, %d, %d, \
0, 2, 4, \
0, 0, 0, \
\'\')\n",
    domain, MAX_DIR_LEVELS, MAX_DIR_LIST-1, MAX_DIR_LIST-1, MAX_DIR_LIST-1);

  pgres = PQexec( pgc, SqlBufUpdate );
  if ( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    fprintf(stderr, "vcreate_dir_control: insert failed: %s\n", 
	    PQresultErrorMessage(pgres));
      return;
  }

  PQclear(pgres);
}

int vdel_dir_control(char *domain)
{
  PGresult *pgres;
  int err;

  if ( (err=vauth_open()) != 0 ) return(err);

  snprintf(SqlBufUpdate, SQL_BUF_SIZE, 
	   "delete from dir_control where domain = '%s'", 
	   domain); 
  pgres=PQexec(pgc, SqlBufUpdate);

  if ( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    PQclear(pgres);
    vcreate_dir_control(domain);
    snprintf(SqlBufUpdate, SQL_BUF_SIZE, 
	     "delete from dir_control where domain = '%s'", 
	     domain); 
    if ( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
      fprintf(stderr, "vdel_dir_control: delete failed[e]: %s\n", 
	      PQresultErrorMessage(pgres));
      err=-1;
    }
  }
  if( pgres ) PQclear(pgres);
  return err;
}

#ifdef ENABLE_AUTH_LOGGING
int vset_lastauth(char *user, char *domain, char *remoteip )
{
  PGresult *pgres;
  int err=0;

  if ( (err=vauth_open()) != 0 ) return(err);

  snprintf( SqlBufUpdate, SQL_BUF_SIZE,
    "UPDATE lastauth SET remote_ip='%s', timestamp=%lu " \
    "WHERE userid='%s' AND domain='%s'", remoteip, time(NULL), user, domain); 

#ifdef DEBUG
fprintf(stderr,"UPDATE command to run is \n\n%s\n\n", SqlBufUpdate);
#endif

  pgres=PQexec(pgc, SqlBufUpdate);

  if (pgres && PQresultStatus(pgres) == PGRES_COMMAND_OK && atoi(PQcmdTuples(pgres)) == 0) {

#ifdef DEBUG
fprintf(stderr,"UPDATE returned OK but had 0 rows\n");
#endif

    if( pgres ) PQclear(pgres);

    snprintf( SqlBufUpdate, SQL_BUF_SIZE,
      "INSERT INTO lastauth (userid, domain, remote_ip, timestamp) " \
      "VALUES ('%s', '%s', '%s', %lu)", user, domain, remoteip, time(NULL)); 

#ifdef DEBUG
fprintf(stderr,"INSERT command to run is \n\n%s\n\n", SqlBufUpdate);
#endif
    pgres=PQexec(pgc, SqlBufUpdate);
    }

/* UPDATE returned 0 rows and/or INSERT failed.  Try creating the table */
  if(!pgres || PQresultStatus(pgres) != PGRES_COMMAND_OK) {
#ifdef DEBUG
fprintf(stderr,"UPDATE and/or INSERT failed.  error was %s\n", PQresultErrorMessage(pgres));
#endif
    if( pgres ) PQclear(pgres);

#ifdef DEBUG
fprintf(stderr, "update returned 0 and/or insert failed in vset_lastauth()\n");
#endif
    vcreate_lastauth_table();

/* and try INSERTing now... */
    snprintf( SqlBufUpdate, SQL_BUF_SIZE,
      "INSERT INTO lastauth (userid, domain, remote_ip, timestamp) " \
      "VALUES ('%s', '%s', '%s', %lu)", user, domain, remoteip, time(NULL)); 

    pgres=PQexec(pgc, SqlBufUpdate);
    }

  if ( !pgres || PQresultStatus(pgres) != PGRES_COMMAND_OK ) {
    fprintf( stderr, "vset_lastauth[f]: %s\n: %s\n", SqlBufUpdate,PQerrorMessage(pgc));
    if( pgres ) PQclear(pgres);
    return (-1);
  }

  if( pgres ) PQclear(pgres);
  return(0);
}
time_t vget_lastauth(struct vqpasswd *pw, char *domain)
{
  PGresult *pgres;
  int err, ntuples;
  time_t mytime;

  if ( (err=vauth_open()) != 0 ) return(err);

  snprintf( SqlBufRead,  SQL_BUF_SIZE, "SELECT timestamp FROM lastauth WHERE userid='%s' AND domain='%s'", pw->pw_name, domain);

  pgres=PQexec(pgc, SqlBufRead);

  if ( !pgres || PQresultStatus(pgres) != PGRES_TUPLES_OK ) {
    if( pgres ) PQclear(pgres);
    vcreate_lastauth_table();
    snprintf( SqlBufRead,  SQL_BUF_SIZE, "SELECT timestamp FROM lastauth WHERE userid='%s' AND domain='%s'", pw->pw_name, domain);
    pgres=PQexec(pgc, SqlBufUpdate);
    if ( !pgres || PQresultStatus(pgres) != PGRES_TUPLES_OK ) {
      fprintf(stderr,"vpgsql: sql error[g]: %s\n", PQerrorMessage(pgc));
      return(0);
    }
  }

  ntuples = PQntuples(pgres);
  mytime = 0;
  if( ntuples ) { /* got something */
    mytime = atol( PQgetvalue(pgres, ntuples-1, 0));
  }
  if( pgres ) PQclear(pgres);
  return(mytime);
}

char *vget_lastauthip(struct vqpasswd *pw, char *domain)
{
  PGresult *pgres;
  static char tmpbuf[100];
  int ntuples=0;

  if ( vauth_open() != 0 ) return(NULL);

  snprintf( SqlBufRead,  SQL_BUF_SIZE, "select remote_ip from lastauth where userid='%s' and domain='%s'",  pw->pw_name, domain);

  pgres=PQexec(pgc, SqlBufRead);
  if ( !pgres || PQresultStatus(pgres) != PGRES_TUPLES_OK ) {
    if( pgres ) PQclear(pgres);
    vcreate_lastauth_table();
    snprintf( SqlBufRead,  SQL_BUF_SIZE, "select remote_ip from lastauth where userid='%s' and domain='%s'", pw->pw_name, domain);

    pgres=PQexec(pgc, SqlBufUpdate);
    if ( !pgres || PQresultStatus(pgres) != PGRES_TUPLES_OK ) {
      fprintf( stderr,"vpgsql: sql error[h]: %s\n", PQerrorMessage(pgc));
      return(NULL);
    }
  }
  ntuples = PQntuples(pgres);
  if( ntuples ) { /* got something */
    strncpy(tmpbuf, PQgetvalue(pgres, ntuples-1, 0),100 );
  }
  if( pgres ) PQclear(pgres);
  return(tmpbuf);
}

void vcreate_lastauth_table()
{
  PGresult *pgres;
  if ( vauth_open() != 0 ) return;

  snprintf( SqlBufCreate, SQL_BUF_SIZE, "CREATE TABLE lastauth ( %s )", 
	    LASTAUTH_TABLE_LAYOUT);

  pgres = PQexec( pgc, SqlBufCreate );
  if ( !pgres || PQresultStatus(pgres) != PGRES_COMMAND_OK ) {
    fprintf(stderr, "vpgsql: vcreate_lastauth_table(): %s\nsql error[i]: %s\n", 
	    SqlBufCreate, PQerrorMessage(pgc));
    return;
  }
  if( pgres ) PQclear( pgres );
  return;
}
#endif

#ifdef VALIAS
char *valias_select( char *alias, char *domain )
{
  PGresult *pgres;
  int err, verrori;

  if ( (err=vauth_open()) != 0 ) {
    verrori = err;
    return(NULL);
  }

  snprintf( SqlBufRead, SQL_BUF_SIZE, 
	    "select valias_line from valias where alias='%s' and domain='%s'",
	    alias, domain );
  if ( ! (pgres=PQexec(pgc, SqlBufRead)) 
       || PQresultStatus(pgres) != PGRES_TUPLES_OK ) {
    if(pgres) PQclear(pgres);
    vcreate_valias_table();
    if ( ! (pgres=PQexec(pgc, SqlBufRead)) 
	 || PQresultStatus(pgres) != PGRES_TUPLES_OK ) {
      fprintf(stderr,"vpgsql: sql error[j]: %s\n", 
	      PQresultErrorMessage(pgres));
      return(NULL);
    }
  }
  if ( PQntuples(pgres) > 0 ) {
    return( PQgetvalue( pgres, 0, 0 ) );
  }
  if(pgres) PQclear(pgres);
  return(NULL);
}

char *valias_select_next()
{
  /* moved contents to last bit of valias_select */
}

int valias_insert( char *alias, char *domain, char *alias_line)
{
  PGresult *pgres;
  int err;

  if ( (err=vauth_open()) != 0 ) return(err);

  while( *alias_line==' ' && *alias_line !=0 ) ++alias_line;
  snprintf( SqlBufUpdate, SQL_BUF_SIZE,
    "insert into valias(alias,domain,valias_line) values ('%s','%s','%s')",
	    alias, domain, alias_line );

  pgres=PQexec( pgc, SqlBufUpdate );
  if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    if(pgres) PQclear(pgres);
    vcreate_valias_table();
    snprintf( SqlBufUpdate, SQL_BUF_SIZE,
    "insert into valias(alias,domain,valias_line) values ('%s','%s','%s')",
	    alias, domain, alias_line );
    pgres=PQexec( pgc, SqlBufUpdate );
    if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
      fprintf(stderr,"vpgsql: sql error[k]: %s\n",PQresultErrorMessage(pgres));
      return(-1);
    }
    if(pgres) PQclear(pgres);
    return(0);
  }
  return(-1);
}

int valias_delete( char *alias, char *domain)
{
  PGresult *pgres;
  int err;

  if ( (err=vauth_open()) != 0 ) return(err);

  snprintf( SqlBufUpdate, SQL_BUF_SIZE, 
	    "delete from valias where alias='%s' and domain='%s'", 
	    alias, domain );
  pgres=PQexec( pgc, SqlBufUpdate );
  if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    if(pgres) PQclear(pgres);
    vcreate_valias_table();
    snprintf( SqlBufUpdate, SQL_BUF_SIZE, 
	      "delete from valias where alias='%s' and domain='%s'", 
	      alias, domain );
    pgres=PQexec( pgc, SqlBufUpdate );
    if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
      fprintf(stderr,"vpgsql: sql error: %s\n", PQresultErrorMessage(pgres));
      return(-1);
    }
  }
  if(pgres) PQclear(pgres);
  return(0);
}

int valias_delete_domain( char *domain)
{
  PGresult *pgres;
  int err;

  if ( (err=vauth_open()) != 0 ) return(err);

  snprintf( SqlBufUpdate, SQL_BUF_SIZE, 
	    "delete from valias where domain='%s'", domain );

  pgres=PQexec( pgc, SqlBufUpdate );
  if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    if(pgres) PQclear(pgres);
    vcreate_valias_table();
    snprintf( SqlBufUpdate, SQL_BUF_SIZE, 
	      "delete from valias where domain='%s'", domain );
    pgres=PQexec( pgc, SqlBufUpdate );
    if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
      fprintf(stderr,"vpgsql: sql error: %s\n", PQresultErrorMessage(pgres));
      return(-1);
    }
  }
  if(pgres) PQclear(pgres);
  return(0);
}

void vcreate_valias_table()
{
  PGresult *pgres;

  if ( vauth_open() != 0 ) return;

  snprintf( SqlBufCreate, SQL_BUF_SIZE, "create table valias ( %s )", 
	    VALIAS_TABLE_LAYOUT );

    pgres=PQexec( pgc, SqlBufUpdate );
    if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
      if( pgres ) PQclear(pgres);
      fprintf(stderr,"vpgsql:sql error[n]:%s\n", PQresultErrorMessage(pgres));
      return;
    }
    if( pgres ) PQclear(pgres);
    return;
}

char *valias_select_all( char *alias, char *domain )
{
  PGresult *pgres;
  int err;

  if ( (err=vauth_open()) != 0 ) return(NULL);

  snprintf( SqlBufRead, SQL_BUF_SIZE, 
	    "select alias, valias_line from valias where domain = '%s'", 
	    domain );
  if ( ! (pgres=PQexec(pgc, SqlBufRead))
       || PQresultStatus(pgres) != PGRES_TUPLES_OK ) {
    if(pgres) PQclear(pgres);
    vcreate_valias_table();
    if ( ! (pgres=PQexec(pgc, SqlBufRead))
         || PQresultStatus(pgres) != PGRES_TUPLES_OK ) {
      fprintf(stderr,"vpgsql: sql error[o]: %s\n",
              PQresultErrorMessage(pgres));
      return(NULL);
    }
  }
  if ( PQntuples(pgres) > 0 ) {
    strcpy( alias, PQgetvalue( pgres, 0, 0 ) );
    return( PQgetvalue( pgres, 0, 1 ) );
  }
  if(pgres) PQclear(pgres);
  return(NULL);
}

char *valias_select_all_next(char *alias)
{
  /* moved to last bit of valias_select_all */
}
#endif

#ifdef ENABLE_PGSQL_LOGGING
int logpgsql(	int verror, char *TheUser, char *TheDomain, char *ThePass, 
		char *TheName, char *IpAddr, char *LogLine) 
{
  PGresult *pgres;
  int err;
  time_t mytime;

  mytime = time(NULL);
  if ( (err=vauth_open()) != 0 ) return(err);
  /*

  snprintf( SqlBufUpdate, SQL_BUF_SIZE,
	    "INSERT INTO vlog set userid='%s', passwd='%s', \
        domain='%s', logon='%s', remoteip='%s', message='%s', \
        error=%i, timestamp=%d", TheUser, ThePass, TheDomain,
        TheName, IpAddr, LogLine, verror, (int)mytime);
  */

  snprintf( SqlBufUpdate, SQL_BUF_SIZE,
  "INSERT INTO vlog (userid,passwd,domain,logon,remoteip,message,error,timestamp values('%s','%s','%s','%s','%s','%s',%i,%d", 
	    TheUser, ThePass, TheDomain, TheName, 
	    IpAddr, LogLine, verror, (int)mytime);

  pgres=PQexec( pgc, SqlBufUpdate );
  if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    if( pgres ) PQclear(pgres);
    vcreate_vlog_table();
  snprintf( SqlBufUpdate, SQL_BUF_SIZE,
  "INSERT INTO vlog (userid,passwd,domain,logon,remoteip,message,error,timestamp values('%s','%s','%s','%s','%s','%s',%i,%d", 
	    TheUser, ThePass, TheDomain, TheName, 
	    IpAddr, LogLine, verror, (int)mytime);

    pgres=PQexec( pgc, SqlBufUpdate );
    if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
      if( pgres ) PQclear(pgres);
      fprintf(stderr,"error inserting into lastauth table\n");
    }
  }
  if( pgres ) PQclear(pgres);
  return(0);
}

void vcreate_vlog_table()
{
  PGresult *pgres;
  if ( vauth_open() != 0 ) return;

  snprintf( SqlBufCreate, SQL_BUF_SIZE, "CREATE TABLE vlog ( %s )",
	    VLOG_TABLE_LAYOUT);

  pgres=PQexec( pgc, SqlBufCreate );
  if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    fprintf(stderr, "could not create lastauth table %s\n", SqlBufCreate);
  }
  if( pgres ) PQclear(pgres);
  return;
}
#endif

void vpgsql_escape( char *instr, char *outstr )
{
  /* escape out " characters */
  while( *instr != 0 ) {
    if ( *instr == '"' ) *outstr++ = '\\';
    *outstr++ = *instr++;
  }

  /* make sure the terminating NULL char is included */
  *outstr++ = *instr++;
}

int vauth_crypt(char *user,char *domain,char *clear_pass,struct vqpasswd *vpw)
{
	  if ( vpw == NULL ) return(-1);

	    return(strcmp(crypt(clear_pass,vpw->pw_passwd),vpw->pw_passwd));
}

