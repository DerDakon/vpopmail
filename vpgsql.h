/*
 *  Pawe³ Niewiadomski <new@linuxpl.org>
 *  Code derived from vmysql.{c,h}
 *
 *  License: GPL v 2
 */
#ifndef VPGSQL_H
#define VPGSQL_H

#include "config.h"

/* Edit to match your set up */ 
#define DB "vpopmail"
#define PG_CONNECT "user=vpopmail dbname=" DB

// char replacing spaces and dashes
#define SQL_DOT_CHAR    '_'

// default table for some operations
#define USERS_TABLE "en_ig_ma"

/* large site table layout */
#define TABLE_LAYOUT "pw_name varchar(32) not null unique, \
pw_passwd varchar(255) default '' not null, \
pw_uid int4, \
pw_gid int4, \
pw_gecos varchar(255), \
pw_dir varchar(255), \
pw_shell varchar(255), \
id int default nextval('user_id') not null unique, \
primary key(id,pw_name)"

#define RELAY_TABLE_LAYOUT "ip_addr varchar(18) not null, timestamp char(12), primary key (ip_addr)"

char *vauth_munch_domain(char *);
int vauth_open();

int vauth_adddomain_size(char *, int);
int vauth_deldomain_size(char *, int);
int vauth_adduser_size(char *, char *, char *, char *, char *, int, int);
int vauth_deluser_size(char *, char *, int);
int vauth_vpasswd_size( char *, char *, char *, int, int);
int vauth_setquota_size( char *, char *, char *, int);
struct passwd *vauth_getpw_size(char *, char *, int);
struct passwd *vauth_user_size(char *, char *, char*, char *, int);
struct passwd *vauth_getall_size(char *, int, int, int);
int vauth_setpw_size( struct passwd *, char *, int);

#define INSERT "insert into  %s \
( pw_name, pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell ) \
values \
( '%s', '%s', %d, 0, '%s', '%s', '%s' )"

#define SELECT "select pw_name, pw_passwd, pw_uid, pw_gid, \
pw_gecos, pw_dir, pw_shell from %s where pw_name = '%s'"

#define GETALL "select pw_name, pw_passwd, pw_uid, pw_gid, pw_gecos, \
pw_dir, pw_shell from %s"

#define SETPW "update %s set pw_passwd = '%s', \
pw_uid = %d, pw_gid = %d, pw_gecos = '%s', pw_dir = '%s', pw_shell = '%s' \
where pw_name = '%s'" 

#ifdef IP_ALIAS_DOMAINS
#define IP_ALIAS_TABLE_LAYOUT "ip_addr varchar(18) not null, domain varchar(255),  primary key(ip_addr)"
#endif

#define DIR_CONTROL_TABLE_LAYOUT "domain varchar(255) not null, cur_users int, \
level_cur int, level_max int, \
level_start0 int, level_start1 int, level_start2 int, \
level_end0 int, level_end1 int, level_end2 int, \
level_mod0 int, level_mod1 int, level_mod2 int, \
level_index0 int , level_index1 int, level_index2 int, the_dir varchar(255), \
primary key(domain)"

#define DIR_CONTROL_SELECT "cur_users, \
level_cur, level_max, \
level_start0, level_start1, level_start2, \
level_end0, level_end1, level_end2, \
level_mod0, level_mod1, level_mod2, \
level_index0, level_index1, level_index2, the_dir"

#endif
