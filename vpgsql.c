/*
 * Pawe³ Niewiadomski, new@linuxpl.org
 * Code derived from vmysql.{c,h}
 *
 * Licence: GPL v 2
 */
#include <pwd.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include <libpq-fe.h>

#include "safestring.h"
#include "vpopmail.h"
#include "vauth.h"
#include "vpgsql.h"

static char is_open = 0;

// PostgreSQL connection
PGconn          *pgc;

void vcreate_relay_table();
void vcreate_dir_control();

/*****************************************************************************
 *
 *****************************************************************************/
int pg_begin(void)
{
    PGresult *pgres;
    pgres=PQexec(pgc, "begin");
    if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK )
        {
            fprintf(stderr, "pg_begin: %s\n", PQresultErrorMessage(pgres));
            return -1;
        }
    PQclear(pgres);
    return 0;
}
/****************************************************************************
 *
 ****************************************************************************/
int pg_end(void)
{
    PGresult *pgres;
    pgres=PQexec(pgc, "end");
    if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK )
        {
            fprintf(stderr, "pg_end: %s\n", PQresultErrorMessage(pgres));
            return -1;
        }
    PQclear(pgres);
    return 0;
}
/*****************************************************************************
 *
 * ***************************************************************************/
int vauth_open()
{
    if ( is_open == 1 ) return(0);

    pgc = PQconnectdb(PG_CONNECT);
    if( PQstatus(pgc) == CONNECTION_BAD)
        {
            fprintf(stderr, "vauth_open: can't connect: %s\n", PQerrorMessage(pgc));
            return VA_NO_AUTH_CONNECTION;
        }
       
    return 0;
}

/*****************************************************************************
 * creates domain table
 * ***************************************************************************/
int vauth_adddomain( char *domain )
{
 char *tmpstr = NULL, *qrbuf=NULL;
 const char cr[]="create table %s ( %s )";
 int err=0;
 PGresult *pgres;
	
	if ( (err=vauth_open()) != 0 ) return(err);
	vset_default_domain( domain );
	
	tmpstr = vauth_munch_domain( domain );

        qrbuf=realloc(qrbuf, strlen(cr)+strlen(tmpstr)+strlen(TABLE_LAYOUT)+1);
        if( qrbuf==NULL || errno== ENOMEM )
            {
                fprintf(stderr, "vauth_adddomain: no mem\n");
                return -1;
            }
                
	sprintf( qrbuf, cr, tmpstr, TABLE_LAYOUT );
        
        pgres=PQexec(pgc, qrbuf);
        free(qrbuf);
        
        if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) 
           { 
               fprintf(stderr, "vauth_adddomain : create table failed : %s\n", 
                                        PQresultErrorMessage(pgres));
               err=-1;
           }
        
        if(pgres) PQclear(pgres);
	return err;
}

/********************************************************************************
 * add user in the given domain
 * ****************************************************************************/
int vauth_adduser(char *user, char *domain, char *pass, 
                  char *gecos, char *dir, int apop )
{
 char *domstr, *quota=NULL, *lqrbuf;
 char dom_dir[156];
 int uid, gid;
 char *dirbuf;
 int err;
 PGresult *pgres;
 
	if ( (err=vauth_open()) != 0 ) return(err);
	vset_default_domain( domain );

#ifdef HARD_QUOTA
	asprintf( &quota, "%d", HARD_QUOTA );
#else
	asprintf( &quota, "NOQUOTA" );
#endif
        if( quota == NULL )
           {
                fprintf(stderr, "vauth_adduser: no mem\n");
                return -1;
           }

	domstr = vauth_munch_domain( domain );
	if ( domain == NULL || domain[0] == 0 ) 
	   {
		domstr = USERS_TABLE;
	        }

	if ( slen(domain) <= 0 ) 
	{
	    if ( slen(dir) > 0 ) 
		{
			asprintf(&dirbuf, "%s/users/%s/%s", VPOPMAILDIR, dir, user);
		} else 
		    {
			asprintf(&dirbuf, "%s/users/%s", VPOPMAILDIR, user);
        	    }
	} else 
	   {
		vget_assign(domain, dom_dir, 156, &uid, &gid );
		if ( slen(dir) > 0 ) 
		{
			asprintf(&dirbuf,"%s/%s/%s", dom_dir, dir, user);
		} else 
		    {
			asprintf(&dirbuf, "%s/%s", dom_dir, user);
		    }
	   }

        if( ! dirbuf )
	     {
	         fprintf(stderr, "vauth_adduser: no mem\n");
	         return -1;
	     }
	     
	asprintf( &lqrbuf, INSERT, domstr, user, pass, apop, gecos, dirbuf, quota);
	free(dirbuf);     
	free(quota);
	
	if( ! lqrbuf || errno==ENOMEM )
	     {
	         fprintf( stderr, "vauth_adduser: no mem\n" );
	         return -1;
	     }
	
        if ( ! (pgres=PQexec(pgc, lqrbuf) ) || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) 
	     {
		 if( pgres )  PQclear(pgres);
		        
		 vauth_adddomain( USERS_TABLE );
		        
        	 if ( ! (pgres=PQexec(pgc, lqrbuf) ) || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) 
			{
			    fprintf(stderr, "vauth_adduser: pgsql: %s\n", PQresultErrorMessage(pgres));
			    free(lqrbuf);
			    if( pgres )  PQclear(pgres);
			        
			    return -1;
			}
             }
        
        free(lqrbuf);
        PQclear(pgres);
        return 0;
}

/*****************************************************************************
 * 
 * ***************************************************************************/
struct passwd *vauth_getpw(char *user, char *domain)
{
 PGresult *pgres;
 char *in_domain;
 char *domstr, *qrbuf=NULL;
 static struct passwd pwent={NULL, NULL, 0, 0, 0, NULL, NULL, NULL, NULL, 0 };
 int err;

	lowerit(user);
	lowerit(domain);

	if( (in_domain = malloc( strlen(domain)+1 )) == NULL )
	   {
	        fprintf( stderr, "vauth_getpw: no mem\n" );
	        return NULL;
	   }
	
	strcpy(in_domain, domain);

	if ( (err=vauth_open()) != 0 ) return NULL;
	
	vset_default_domain( in_domain );

	domstr = vauth_munch_domain( in_domain );
	free(in_domain);
	
	if ( domstr == NULL || domstr[0] == 0 )
		domstr = USERS_TABLE;

        qrbuf=realloc( qrbuf, strlen(SELECT)+strlen(domstr)+strlen(user)+1);
        if( qrbuf==NULL || errno==ENOMEM )
           {
                fprintf(stderr, "vauth_getpw: no mem\n");
                return NULL;
           }
           
	sprintf( qrbuf, SELECT, domstr, user );
	
        pgres=PQexec(pgc, qrbuf);
        free(qrbuf);
        
	if ( ! pgres || PQresultStatus(pgres)!=PGRES_TUPLES_OK)
	{
		if( pgres )     PQclear(pgres);
		printf("vauth_getpw: failed select: %s\n", PQresultErrorMessage(pgres));
		return NULL;
	}
        
        if ( PQntuples(pgres) <= 0 ) // rows count
        {
		PQclear(pgres);
		return NULL;
	}

	pwent.pw_name=realloc(pwent.pw_name, PQgetlength(pgres, 0, 0)+1 );
	pwent.pw_passwd=realloc(pwent.pw_passwd, PQgetlength(pgres, 0, 1)+1 );
	// here we have pw_uid, pw_gid
	pwent.pw_gecos=realloc(pwent.pw_gecos, PQgetlength(pgres, 0, 4)+1 );
	pwent.pw_dir=realloc(pwent.pw_dir, PQgetlength(pgres, 0, 5)+1 );
	pwent.pw_shell=realloc(pwent.pw_shell, PQgetlength(pgres, 0, 6)+1 );

	if( !pwent.pw_name || !pwent.pw_passwd || ! pwent.pw_gecos
	     || !pwent.pw_dir || !pwent.pw_shell || errno==ENOMEM )
	     {
	        fprintf(stderr, "vauth_getpw: no mem\n");
	        PQclear(pgres);
	        return NULL;
	     }

	strcpy(pwent.pw_name, PQgetvalue( pgres, 0, 0 ) );
	strcpy(pwent.pw_passwd, PQgetvalue( pgres, 0, 1 ) );
	
	pwent.pw_uid    = atoi(PQgetvalue( pgres, 0, 2 ));
	pwent.pw_gid    = atoi(PQgetvalue( pgres, 0, 3 ));
		
	strcpy(pwent.pw_gecos, PQgetvalue( pgres, 0, 4 ));
	strcpy(pwent.pw_dir, PQgetvalue( pgres, 0, 5 ));
	strcpy(pwent.pw_shell, PQgetvalue( pgres, 0, 6 ));
	
	PQclear(pgres);
	return &pwent;
}

/****************************************************************************
 * deletes domain of given name
 * **************************************************************************/
int vauth_deldomain( char *domain )
{
 PGresult *pgres;
 const char dtb[]="drop table %s";
 char *tmpstr, *qrbuf=NULL;
 int err;
	
	qrbuf=realloc(qrbuf, strlen(dtb)+strlen(domain)+1);
	if( qrbuf == NULL || errno==ENOMEM )
            {
	        fprintf(stderr, "vauth_deldomain: no mem\n");
	        return -1;      // no mem :-(
	    }
	
	if ( (err=vauth_open()) != 0 ) return(err);
	vset_default_domain( domain );
	tmpstr = vauth_munch_domain( domain );
	
	sprintf( qrbuf, dtb, tmpstr );     // fill it

        pgres=PQexec(pgc, qrbuf);
        free(qrbuf);
	
	if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK) 
	   {
	        fprintf(stderr, "vauth_deldomain: pgsql query: %s", PQresultErrorMessage(pgres));
	        err= -1;
	   }else err=0;
        
        if(pgres) PQclear(pgres);
	return err;
}

/*****************************************************************************
 * deletes user from table
 * ***************************************************************************/
int vauth_deluser( char *user, char *domain )
{
 PGresult *pgres;
 const char delus[]="delete from %s where pw_name='%s'";
 char *tmpstr, *qrbuf=NULL;
 int err;
	
	if ( (err=vauth_open()) != 0 ) return(err);
	vset_default_domain( domain );

	if ( domain == NULL || domain[0] == 0 ) 
		tmpstr = USERS_TABLE;
	  else  tmpstr = vauth_munch_domain( domain );
	        
	qrbuf=realloc( qrbuf, strlen( delus )+strlen(tmpstr)+strlen(user)+1 );
	if( qrbuf== NULL || errno==ENOMEM )
	    {
	        fprintf(stderr, "vauth_deluser: no mem\n");
	        return -1; // no mem
	    }

        sprintf( qrbuf, delus, tmpstr, user );
                                
        pgres=PQexec(pgc, qrbuf);
        free(qrbuf);
        
        if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) 
            {
                err=-1;
	        fprintf(stderr, "vauth_deluser: query failed: %s\n", PQresultErrorMessage(pgres));
	    } else err=0;
        
        if( pgres ) PQclear(pgres);
        return err;
}

/******************************************************************************
 * set user's quota
 * ****************************************************************************/
int vauth_setquota( char *username, char *domain, char *quota )
{
 PGresult *pgres;
 const char setq[]="update %s set pw_shell='%s' where pw_name='%s'";
 char *tmpstr, *qrbuf=NULL;
 int err;

    if ( strlen(username) > MAX_PW_NAME ) return(VA_USER_NAME_TOO_LONG);
    if ( strlen(username) == 1 ) return(VA_ILLEGAL_USERNAME);
    if ( strlen(domain) > MAX_PW_DOMAIN ) return(VA_DOMAIN_NAME_TOO_LONG);
    if ( strlen(quota) > MAX_PW_QUOTA )    return(VA_QUOTA_TOO_LONG);

	
	if ( (err=vauth_open()) != 0 ) return(err);
	vset_default_domain( domain );

	tmpstr = vauth_munch_domain( domain );

        qrbuf=realloc( qrbuf, strlen(setq) + strlen(tmpstr) + strlen(quota) + strlen(username)+1 );
        if( qrbuf== NULL || errno==ENOMEM )
                return -1;

	sprintf( qrbuf, setq, tmpstr, quota, username );

        pgres=PQexec(pgc, qrbuf);
        free(qrbuf);
        
	if( pgres && PQresultStatus(pgres)==PGRES_COMMAND_OK)
	                err=0;
	        else 
        	{
	        	fprintf(stderr, "vauth_setquota: query failed: %s\n", PQresultErrorMessage(pgres));
	        	err = -1;
	        }
	
	if( pgres ) PQclear(pgres);
        return err;
}

/******************************************************************************
 * sets password for given user
 * ****************************************************************************/
int vauth_vpasswd( char *user, char *domain, char *pass, int apop )
{
 PGresult *pgres;
 const char update[]="update %s set pw_passwd='%s' where pw_name='%s'";
 char *tmpstr, *qrbuf=NULL;
 uid_t myuid;
 int err;

 	myuid = geteuid();
	if ( myuid != VPOPMAILUID && myuid != 0 ) 
		return  VA_BAD_UID;

	if ( (err=vauth_open()) != 0 ) return(err);
	vset_default_domain( domain );

	tmpstr = vauth_munch_domain( domain );
	qrbuf=realloc(qrbuf, strlen(update)+strlen(tmpstr)+strlen(pass)+strlen(user)+1);
	if( qrbuf==NULL || errno==ENOMEM )
	        return -1;
	        
	sprintf( qrbuf, update, tmpstr, pass, user );

        pgres=PQexec(pgc, qrbuf);
        free(qrbuf);
        
	if( pgres && PQresultStatus(pgres)==PGRES_COMMAND_OK) 
	                err=0;
	        else 
        	{
	        	fprintf(stderr, "vauth_vpasswd: pgsql query : %s\n", PQresultErrorMessage(pgres));
	        	err = -1;
	        }
	
	if( pgres ) PQclear(pgres);
	return err;
}

/****************************************************************************
 * gets all entries for given domain
 * **************************************************************************/
struct passwd *vauth_getall(char *domain, int first, int sortit )
{
 static PGresult *pgres=NULL;
 char *domstr = NULL, *qrbuf=NULL;
 const char order[]=" order by pw_name";
 static struct passwd pwent={NULL, NULL, 0, 0, 0, NULL, NULL, NULL, NULL, 0 };
 static unsigned ntuples=0, ctuple=0;      // ntuples - number of tuples
                                      // ctuple - current tuple
 int err;

	vset_default_domain( domain );
	domstr = vauth_munch_domain( domain );
        
        if ( first == 1 ) 
	{
	    if ( pgres )     // reset state if we had previus result
	        {
	            PQclear(pgres);    // clear previous result
	            ntuples=ctuple=0;
	        }
	        
	    if ( (err=vauth_open()) != 0 ) return(NULL);

	    qrbuf=realloc( qrbuf, strlen(GETALL) + strlen(domstr) + strlen(order) + 1);
	    if( qrbuf==NULL || errno==ENOMEM )
	        {
	            fprintf(stderr, "vauth_getall: no mem\n");
	            return NULL;
	        }
	        
	    sprintf( qrbuf, GETALL, domstr );
	    
	    if ( sortit == 1 )
		strcat( qrbuf, order);
        
            pgres=PQexec(pgc, qrbuf);
            free(qrbuf);
            
            if( !pgres || PQresultStatus(pgres) != PGRES_TUPLES_OK )
                {
		    if( pgres ) PQclear(pgres);
		    printf("vauth_getall: query failed: %s\n", PQresultErrorMessage(pgres));
		    return NULL;
		}
	    ntuples=PQntuples(pgres);
	} 
	
	if ( ctuple == ntuples ) 
	{
	    PQclear(pgres);
	    ctuple=ntuples=0;
	    return NULL;
	}
		    
        // may be we should only change ptrs (i.e. pw_name=PQntuple(...) ??)
        // it'd take less memory
        // TODO: check what happens with returned struct
	pwent.pw_name   = realloc(pwent.pw_name,  PQgetlength(pgres, ctuple, 0)+1);
	pwent.pw_passwd = realloc(pwent.pw_passwd,PQgetlength(pgres, ctuple, 1)+1);
	pwent.pw_gecos  = realloc(pwent.pw_gecos, PQgetlength(pgres, ctuple, 4)+1);
	pwent.pw_dir    = realloc(pwent.pw_dir,   PQgetlength(pgres, ctuple, 5)+1);
	pwent.pw_shell  = realloc(pwent.pw_shell, PQgetlength(pgres, ctuple, 6)+1);
	if( !pwent.pw_shell || !pwent.pw_dir || !pwent.pw_gecos 
	    || !pwent.pw_passwd || !pwent.pw_name || errno==ENOMEM )
	        {
	              PQclear(pgres);
	              ctuple=ntuples=0;
	              fprintf(stderr, "vauth_getall: no mem\n");
	              return NULL;
	        }

	strcpy(pwent.pw_name, PQgetvalue( pgres, ctuple, 0 ) );
	strcpy(pwent.pw_passwd, PQgetvalue( pgres, ctuple, 1 ) );
	
	pwent.pw_uid    = atoi(PQgetvalue( pgres, ctuple, 2 ));
	pwent.pw_gid    = atoi(PQgetvalue( pgres, ctuple, 3 ));
	
	strcpy(pwent.pw_gecos, PQgetvalue( pgres, ctuple, 4 ));
	strcpy(pwent.pw_dir, PQgetvalue( pgres, ctuple, 5 ));
	strcpy(pwent.pw_shell, PQgetvalue( pgres, ctuple, 6 ));
        
        ctuple++;
        return(&pwent);
}

/***************************************************************************
 * 2001-03-15, new
 * *************************************************************************/
char *vauth_munch_domain( char *domain )
{
    static char *tmp=NULL;
    char * ptr;

    if ( domain == NULL || ! *domain ) 
            return domain;

    if( (tmp=realloc(tmp, strlen(domain)+1)) == NULL )
        {
            fprintf(stderr, "vauth_munch_domain: no mem\n");
            return NULL;    // 
        }
    
    ptr=tmp;
	
    while( *domain )
        {
	    if ( *domain == '.' || *domain == '-' )
                   *ptr = SQL_DOT_CHAR;
             else  *ptr=*domain;
            
            ptr++;
            domain++;
        }

    *ptr='\0';  // string finished
    
    return tmp;
}

/****************************************************************************
 * set pw 
 * **************************************************************************/
int vauth_setpw( struct passwd *inpw, char *domain )
{
 PGresult *pgres;
 char *tmpstr=NULL, *domstr=NULL;
 uid_t myuid;
#ifdef SQWEBMAIL_PASS
 uid_t uid;
 gid_t gid;
#endif
 int err;

    err = vcheck_vqpw(inpw, domain);
    if ( err != 0 ) return(ret);

 	myuid = geteuid();
	if ( myuid != VPOPMAILUID && myuid != 0 ) 
 	   {
		return VA_BAD_UID;
	   }

	if ( (err=vauth_open()) != 0 ) return(err);
	vset_default_domain( domain );

	domstr = vauth_munch_domain( domain );
	
	asprintf( &tmpstr, SETPW, domstr, inpw->pw_passwd, inpw->pw_uid,
			inpw->pw_gid, inpw->pw_gecos, inpw->pw_dir, 
			inpw->pw_shell, inpw->pw_name );
			
	pgres=PQexec(pgc, tmpstr);
	free(tmpstr);
	
	if ( !pgres || PQresultStatus(pgres)!= PGRES_COMMAND_OK )
	   {
		fprintf(stderr, "vauth_setpw: pgsql query: %s\n", PQresultErrorMessage(pgres));
		if( pgres )     PQclear(pgres);
		return -1;
	   }
        if( pgres ) PQclear(pgres);

#ifdef SQWEBMAIL_PASS
	tmpstr = vget_assign(domain, NULL, 156, &uid, &gid );
	vsqwebmail_pass( inpw->pw_dir, inpw->pw_passwd, uid, gid);
#endif

	return 0;
}

/*************************************************************************
 * 
 * ***********************************************************************/
void vopen_smtp_relay()
{
 PGresult *pgres;
 char *ipaddr, *lqrbuf=NULL;
 time_t mytime;
 int err;

    mytime = time(NULL);
    if ( (ipaddr = getenv("TCPREMOTEIP")) )
               return;
    
    if ( ipaddr != NULL && *ipaddr == ':') 
        {
	   ipaddr +=2;
	   while(*ipaddr!=':') ++ipaddr;
	   ++ipaddr;
	}

    if ( (err=vauth_open()) != 0 ) exit(err);

    asprintf( &lqrbuf, "replace into relay ( ip_addr, timestamp ) values ( '%s', %d )",
                        ipaddr, (int)mytime);

    if( lqrbuf == NULL || errno==ENOMEM )
        {
            fprintf( stderr, "vopen_smtp_relay: no mem\n" );
            return;
        }        
            
    if ( ! (pgres=PQexec( pgc, lqrbuf)) || PQresultStatus(pgres)!= PGRES_COMMAND_OK )
    {
        if( pgres )     PQclear(pgres);
        
        vcreate_relay_table();

        if (! (pgres=PQexec( pgc, lqrbuf)) || PQresultStatus(pgres)!= PGRES_COMMAND_OK ) 
        {
            fprintf(stderr, "can't insert into ip_addr table: %s\n", PQresultErrorMessage(pgres));
        }
    }

    if( pgres ) PQclear(pgres);
    return;
}

/*************************************************************************
 *
 * ***********************************************************************/
void vupdate_rules(int fdm)
{
    PGresult *pgres;
    const char *qr="select ip_addr from relay";
    const char re[]=":allow,RELAYCLIENT=\"\"\n";
    register unsigned i=0, n, len=strlen(re)+1;
    char *buf=NULL;
    
    	if ( vauth_open() != 0 ) return;
    	
	if ( !(pgres=PQexec(pgc, qr)) || PQresultStatus(pgres)!=PGRES_TUPLES_OK ) 
	{
		vcreate_relay_table();
		if(pgres) PQclear(pgres);
		
		if ( !(pgres=PQexec(pgc, qr)) || PQresultStatus(pgres)!=PGRES_TUPLES_OK )
		   {
			printf("vupdate_rules: query : %s\n", 
			                PQresultErrorMessage(pgres));
			return;
		   }
	}
        n=PQntuples(pgres);
        for( ; i < n ; i++ )
           {
		buf=realloc(buf, len+PQgetlength(pgres, i, 0) );
                if( buf==NULL || errno==ENOMEM )
	           {
		      PQclear(pgres);
		      free(buf);
		      fprintf(stderr, "vupdate_rules: no mem\n");
		      return;
		   }
		  
		sprintf( buf, "%s%s", PQgetvalue(pgres, i, 0), re );
		if( write( fdm, buf, strlen(buf) ) != strlen(buf) )
		  {
		     fprintf(stderr, "vupdate_rules: short write: %s", 
		                                strerror(errno));
                     break;
		  }
	   }
        PQclear(pgres);
        free(buf);
}

/*************************************************************************
 * clear old entries in relay table
 * ***********************************************************************/
void vclear_open_smtp(time_t clear_minutes, time_t mytime)
{
 PGresult *pgres;
 time_t delete_time;
 const char del[]="delete from relay where timestamp <= %d"; 
 char *buf=NULL;
	
#warning why do we have exit here ? (not return ?)
	if ( vauth_open() ) exit(0);
	delete_time = mytime - clear_minutes;

        // this function allocates needed space
	asprintf( &buf, del, (int) delete_time );
        
        if( buf == NULL || errno == ENOMEM )
                return;
                
        pgres=PQexec(pgc, buf);
	free(buf);
	
	if( !pgres || PQresultStatus(pgres) != PGRES_COMMAND_OK) 
                vcreate_relay_table();
        
        if( pgres ) PQclear(pgres);
		  
	return;
}

/***************************************************************************
 * create realy table
 * *************************************************************************/
void vcreate_relay_table()
{
  PGresult *pgres;
  char *qrbuf=NULL;
  const char cr[]="create table relay ( %s )";
  
        qrbuf=realloc(qrbuf, strlen(cr)+strlen(RELAY_TABLE_LAYOUT)+1);
        if( qrbuf==NULL || errno==ENOMEM )
           {
                fprintf(stderr, "vcreate_relay_table: no mem\n");
                return;
           }
           
	sprintf( qrbuf, cr, RELAY_TABLE_LAYOUT );
	
	pgres=PQexec(pgc, qrbuf);
	free(qrbuf);
	
	if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK)
       		fprintf(stderr, "vcreate_relay_table: create failed: %s \n", PQresultErrorMessage(pgres));

        if(pgres) PQclear(pgres);		  
	return;
}

/*****************************************************************************
 * ???
 * ***************************************************************************/
int vmkpasswd( char *domain )
{
	return(0);
}

/******************************************************************************
 *
 * ***************************************************************************/
void vclose()
{
	/* disconnection from the database */
	if ( is_open == 1 ) 
	{
		is_open = 0;
		PQfinish(pgc);
	}
}

/***************************************************************************
 *
 ***************************************************************************/
#ifdef IP_ALIAS_DOMAINS

/**************************************************************************
 * create ip map table
 * ************************************************************************/
void vcreate_ip_map_table()
{
  PGresult *pgres;
  const char ipmap[]="create table ip_alias_map ( %s )";
  char *qrbuf=NULL;
  
	if ( vauth_open() != 0 ) return;

	qrbuf=realloc(qrbuf, strlen(ipmap)+strlen(IP_ALIAS_TABLE_LAYOUT)+1);
	if( qrbuf==NULL || errno==ENOMEM )
	    {
	        fprintf(stderr, "vcreate_ip_map_table: no mem\n");
	        return;
	    }
	    
	sprintf( qrbuf, ipmap, IP_ALIAS_TABLE_LAYOUT);

	pgres=PQexec(pgc, qrbuf);
	free(qrbuf);
	
	if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK)
	  	    fprintf(stderr, "vcreate_ip_map_table: %s\n", PQresultErrorMessage(pgres));
        
        if( pgres )   PQclear(pgres);
        return;
}

/****************************************************************************
 *
 * **************************************************************************/
int vget_ip_map( char *ip, char *domain, int domain_size)
{
 PGresult *pgres;
 const char se[]="select domain from ip_alias_map where ip_addr = '%s'";
 char *ptr, *qrbuf=NULL;
 unsigned ntuples;

	if ( ip == NULL || slen(ip) <= 0 ) return(-1);
	if ( domain == NULL ) return(-2);
	if ( vauth_open() != 0 ) return(-3);

        qrbuf=realloc( qrbuf, strlen(se)+strlen(ip)+1);
        if( !qrbuf || errno==ENOMEM )
            {
                fprintf(stderr, "vget_ip_map: no mem\n");    
                return -1;
            }
        
        sprintf( qrbuf, se, ip);
        
        pgres=PQexec(pgc, qrbuf);
        free(qrbuf);
        if( !pgres || PQresultStatus(pgres) != PGRES_TUPLES_OK )
           {
               fprintf( stderr, "vget_ip_map: pgsql query: %s\n", PQerrorMessage(pgc));
               if( pgres ) PQclear(pgres);
               return -1;
           }
        
        ntuples = PQntuples(pgres);
        if(!ntuples)
                *domain='\0';
          else {
                 ptr = PQgetvalue(pgres, ntuples-1, 0);
                 strncpy(domain, ptr, strlen(ptr) );
               }
		
        PQclear(pgres);     
	return 0;
}

/*****************************************************************************
 * 
 * ***************************************************************************/
int vadd_ip_map( char *ip, char *domain) 
{
   PGresult *pgres;
   const char se[]="insert into ip_alias_map ( ip_addr, domain ) values ( '%s', '%s' )";
   const char de[]="delete from ip_alias_map where ip_addr='%s'";
   char *qrbuf=NULL;
   
	if ( ip == NULL || slen(ip) <= 0 ) return(-1);
	if ( domain == NULL || slen(domain) <= 0 ) return(-1);
	if ( vauth_open() != 0 ) return(-1);

        qrbuf=realloc(qrbuf, strlen(de)+strlen(ip)+1);
        if( !qrbuf || errno==ENOMEM )
            {
                fprintf(stderr, "vadd_ip_map: no mem\n");
                return -1;
            }
        
        if( pg_begin() )     // begin transaction
            {
                free(qrbuf);
                return -1;
            }

        /* delete previous entry */
        sprintf(qrbuf, de, ip);
        pgres=PQexec(pgc, qrbuf);
        if( pgres ) PQclear(pgres); /* don't check pgres status - table could not exist */

        /* reallocate space */
        qrbuf=realloc(qrbuf, strlen(se)+strlen(ip)+strlen(domain)+1);
        if( !qrbuf || errno==ENOMEM )
            {
                fprintf(stderr, "vadd_ip_map: no mem\n");
                return -1;
            }
            
        sprintf( qrbuf, se, ip, domain);
        
        /* insert new data */
        pgres=PQexec(pgc, qrbuf);
        if ( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK )
           {
                if( pgres ) PQclear(pgres);
                vcreate_ip_map_table();
    	        
    	        qrbuf=realloc(qrbuf, strlen(se)+strlen(ip)+strlen(domain)+1);
                if( !qrbuf || errno==ENOMEM )
                   {
                        free(qrbuf);
                        fprintf(stderr, "vadd_ip_map: no mem\n");
                        return -1;
                   }

                pgres=PQexec( pgc, qrbuf );
    	        if ( !pgres || PQresultStatus(pgres) != PGRES_COMMAND_OK ) 
    	           {
	               fprintf( stderr, "vadd_ip_map: insert: %s\n", PQerrorMessage(pgc));
	               if( pgres ) PQclear(pgres);
	               free(qrbuf);
	               return -1;
    	           }
           }

        free(qrbuf);   
        PQclear(pgres);
        
        return pg_end();
}

/*****************************************************************************
 *
 * ***************************************************************************/
int vdel_ip_map( char *ip, char *domain) 
{
  PGresult *pgres;
  const char del[]="delete from ip_alias_map where ip_addr = '%s' and domain = '%s'";
  char *qrbuf=NULL;

	if ( ip == NULL || slen(ip) <= 0 ) return -1;
	if ( domain == NULL || slen(domain) <= 0 ) return -1;
	if ( vauth_open() != 0 ) return -1;

        qrbuf=realloc(qrbuf, strlen(del)+strlen(ip)+strlen(domain)+1);
        if(qrbuf == NULL || errno==ENOMEM)
           {
                fprintf(stderr, "vdel_ip_map: no mem\n");
                return -1;
           }
           
	sprintf( qrbuf, del, ip, domain);

	pgres=PQexec(pgc, qrbuf);
	free(qrbuf);
	
	if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK )
	      	{
        	    fprintf(stderr, "vdel_ip_map: delete failed: %s\n", PQresultErrorMessage(pgres));
        	    if(pgres) PQclear(pgres);
        	    return -1;
                }
                
        PQclear(pgres);
	return 0;
}

/******************************************************************************
 *
 * ****************************************************************************/
int vshow_ip_map( int first, char *ip, char *domain )
{
 static PGresult *pgres=NULL;
 static unsigned ntuples=0, ctuple=0;
 const char qr[]="select ip_addr, domain from ip_alias_map";

	if ( ip == NULL ) return -1;
	if ( domain == NULL ) return -1;
	if ( vauth_open() != 0 ) return -1;

	if ( first == 1 ) 
	   {
		if (pgres)
		   {
		      PQclear(pgres);
		      ntuples=ctuple=0;
		   }
		
		if ( vauth_open() ) return -1;

        	if ( ! (pgres=PQexec(pgc, qr)) 
        	        || PQresultStatus(pgres) != PGRES_TUPLES_OK ) 
        	   {
			if(pgres) PQclear(pgres);
			fprintf(stderr, "vshow_ip_map: pgres: %s\n", PQresultErrorMessage(pgres));
			return -1;
	           }
	        
	        ntuples=PQntuples(pgres);
	    } 
        
        if ( ctuple == ntuples )
            {
                PQclear(pgres);
                ntuples=ctuple=0;
                return 0;
            }
	
	strncpy( ip, PQgetvalue( pgres, ctuple, 0), 18); 
	strncpy( domain, PQgetvalue( pgres, ctuple, 1), 156); 
        
        ctuple++;
        return 1;
}
#endif

/*************************************************************************
 *
 * ***********************************************************************/
void def_dir_ctl( vdir_type *vdir )
{
	register int i;

	vdir->cur_users = 0;
	for ( i=0; i<MAX_DIR_LEVELS; ++i )
	   {
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
/**************************************************************************
 *
 **************************************************************************/
int vread_dir_control(vdir_type *vdir, char *domain, uid_t uid, gid_t gid)
{
 PGresult *pgres;
 const char qr[]="select %s from dir_control where domain='%s'";
 char *lqrbuf=NULL;
 char found = 0;

    if ( vauth_open() != 0 ) return(-1);
    
    lqrbuf=realloc(lqrbuf, strlen(DIR_CONTROL_SELECT)+strlen(domain)+1);
    if( lqrbuf==NULL || errno==ENOMEM )
        {
            fprintf(stderr, "vread_dir_control: no mem\n");
            return -1;
        }
    sprintf(lqrbuf, qr, DIR_CONTROL_SELECT, domain );
    
    if ( ! (pgres=PQexec(pgc, lqrbuf)) || PQresultStatus(pgres)!=PGRES_TUPLES_OK ) 
    {
        if( pgres ) PQclear(pgres);
        
        vcreate_dir_control(domain);

    	if ( ! (pgres=PQexec(pgc, lqrbuf)) || PQresultStatus(pgres)!=PGRES_TUPLES_OK )
    	   {
		free(lqrbuf);
		fprintf(stderr, "vread_dir_control: pgsql: %s", PQresultErrorMessage(pgres));
		return -1;
    	   }
    }
    free(lqrbuf);

    if ( PQntuples(pgres) > 0 ) 
    {
        found++;
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
    
    if ( found == 0 ) 
        def_dir_ctl(vdir);
    
    return 0;
}

/****************************************************************************
 *
 * **************************************************************************/
int vwrite_dir_control(vdir_type *vdir, char *domain, int uid, int gid)
{
    PGresult *pgres;
    char *lqrbuf=NULL;
    const char de[]="delete from dir_control where domain='%s'";

    if ( vauth_open() != 0 ) return -1;
    
    lqrbuf=realloc(lqrbuf, strlen(de)+strlen(domain));
    if(lqrbuf==NULL || errno==ENOMEM )
        {
            fprintf(stderr, "vwrite_dir_control: no mem\n");
        }

    if( pg_begin() )
        {
            free(lqrbuf);
            return -1;
        }
    
    sprintf(lqrbuf, de, domain);
    pgres=PQexec(pgc, lqrbuf);
    free(lqrbuf);
    lqrbuf=NULL;
    
    if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK )
        {
            fprintf(stderr, "vwrite_dir_control: delete failed: %s", PQresultErrorMessage(pgres));
            return -1;
        }
    
    asprintf( &lqrbuf, "insert into dir_control ("
                      "domain, cur_users,"
                      "level_cur, level_max,"
                      "level_start0, level_start1, level_start2,"
                      "level_end0, level_end1, level_end2,"
                      "level_mod0, level_mod1, level_mod2,"
                      "level_index0, level_index1, level_index2, the_dir )"
                      " values('%s', %lu, %d, %d, %d, %d, %d, %d, %d, %d, "
                      "%d, %d, %d, %d, %d, %d, '%s')",
                      domain, vdir->cur_users, vdir->level_cur, 
                      vdir->level_max, vdir->level_start[0], 
                      vdir->level_start[1], vdir->level_start[2],
                      vdir->level_end[0], vdir->level_end[1], 
                      vdir->level_end[2], vdir->level_mod[0], 
                      vdir->level_mod[1], vdir->level_mod[2],
                      vdir->level_index[0], vdir->level_index[1], 
                      vdir->level_index[2], vdir->the_dir);
    if( !lqrbuf ) 
        {
            fprintf(stderr, "vwrite_dir_control: no mem\n");
            return -1;
        }
        
    pgres=PQexec(pgc, lqrbuf );
    free(lqrbuf);
    
    if ( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK )
        {
	    fprintf(stderr, "vwrite_dir_control: %s\n", PQresultErrorMessage(pgres));
	    return(-1);
	}

    PQclear(pgres);
    
    return pg_end();
}

/****************************************************************************
 *
 * **************************************************************************/
void vcreate_dir_control(char *domain)
{
    PGresult *pgres;
    const char cr[]="create table dir_control (%s)";
    char *lqrbuf=NULL;
    
    if ( vauth_open() != 0 ) return;

    lqrbuf=realloc(lqrbuf, strlen(cr)+strlen(DIR_CONTROL_TABLE_LAYOUT)+1);
    if( lqrbuf== NULL || errno==ENOMEM )
        {
            fprintf(stderr, "vcreate_dir_control: no mem\n");
            return;
        }
        
    sprintf(lqrbuf, cr, DIR_CONTROL_TABLE_LAYOUT	);
    pgres=PQexec( pgc, lqrbuf );
    free(lqrbuf);
    lqrbuf=NULL;
    
    if( ! pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK )
        {
		fprintf(stderr, "vcreate_dir_control: pgsql query: %s\n", PQresultErrorMessage(pgres));
		return;
	}
	
    if( pgres ) PQclear(pgres);

	asprintf( &lqrbuf, "insert into dir_control ( "
                          "domain, cur_users,"
                          "level_cur, level_max,"
                          "level_start0, level_start1, level_start2,"
                          "level_end0, level_end1, level_end2,"
                          "level_mod0, level_mod1, level_mod2,"
                          "level_index0, level_index1, level_index2, the_dir )"
                          " values ('%s', '0',"
                          "'0', %d,'0', '0', '0','%d', '%d', '%d',"
                          "'0', '2', '4','0', '0', '0','')\n",
                          domain, MAX_DIR_LEVELS, MAX_DIR_LIST-1, 
                          MAX_DIR_LIST-1, MAX_DIR_LIST-1 );

        if( ! lqrbuf )
            {
                fprintf(stderr, "vcreate_dir_control: no mem\n");
                return;
            }
        
        pgres=PQexec(pgc, lqrbuf);
        free(lqrbuf);
        
	if ( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK )
	    {
		fprintf(stderr, "vcreate_dir_control: insert failed: %s\n", PQresultErrorMessage(pgres));
		return;
	    }

        PQclear(pgres);
}

/***************************************************************************
 * delete sth ;-)
 * *************************************************************************/
int vdel_dir_control(char *domain)
{
 PGresult *pgres;
 int err;
 char *qrbuf=NULL;
 const char del[]="delete from dir_control where domain='%s'";
        
        if ( (err=vauth_open()) != 0 ) return   err;
        
        qrbuf=realloc( qrbuf, strlen(del)+strlen(domain)+1);
        if( qrbuf==NULL || errno==ENOMEM )
            {
                fprintf(stderr, "vdel_dir_control: no mem\n");
                return -1;
            }
                
	sprintf( qrbuf, del, domain); 
        
	pgres=PQexec(pgc, qrbuf);
	free(qrbuf);
	
	if( pgres && PQresultStatus(pgres)==PGRES_COMMAND_OK) 
	                err=0;
	        else 
        	{
        	    fprintf(stderr, "vdel_dir_control: delete failed: %s\n", PQresultErrorMessage(pgres));
        	    err=-1;
                }
        if( pgres ) PQclear(pgres);
        return err;
}
