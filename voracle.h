/*
 * voracle.h
 * part of the vchkpw package
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
#ifndef VPOPMAIL_ORACLE_H
#define VPOPMAIL_ORACLE_H

/* Edit to match your set up */ 
#define ORACLE_SERVICE       "jimmy"
#define ORACLE_USER          "system"
#define ORACLE_PASSWD        "manager"
#define ORACLE_HOME          "ORACLE_HOME=/export/home/oracle"
/* End of setup section*/

/* defaults - no need to change */
#define ORACLE_DEFAULT_TABLE "vpopmail"
#define ORACLE_DATABASE      "orcl1"
#define ORACLE_DOT_CHAR '_'
#define ORACLE_LARGE_USERS_TABLE "users"

/* small site table layout */
#define SMALL_TABLE_LAYOUT "pw_name char(32) not null, \
pw_domain varchar(223) not null, \
pw_passwd varchar(255) not null, \
pw_uid int, \
pw_gid int, \
pw_gecos varchar(255), \
pw_dir varchar(255), \
pw_shell varchar(255), primary key(pw_name, pw_domain)"

#define SMALL_TABLE_LAYOUT_CLEAR "pw_name char(32) not null, \
pw_domain varchar(223) not null, \
pw_passwd varchar(255) not null, \
pw_uid int, \
pw_gid int, \
pw_gecos varchar(255), \
pw_dir varchar(255), \
pw_shell varchar(255), \
pw_clear_passwd varchar(255), \
primary key (pw_name, pw_domain) "


/* large site table layout */
#define LARGE_TABLE_LAYOUT "pw_name char(32) not null, \
pw_passwd varchar(255) not null, \
pw_uid int, \
pw_gid int, \
pw_gecos varchar(255), \
pw_dir varchar(255), \
pw_shell varchar(255), primary key(pw_name)"

/* large site clear password table layout */
#define LARGE_TABLE_LAYOUT_CLEAR "pw_name char(32) not null, \
pw_passwd varchar(255) not null, \
pw_uid int, \
pw_gid int, \
pw_gecos varchar(255), \
pw_dir varchar(255), \
pw_shell varchar(255), \
pw_clear_passwd varchar(255), \
primary key(pw_name)"

#define RELAY_TABLE_LAYOUT "ip_addr char(18) not null, timestamp bigint primary key(ip_addr)"

#define LASTAUTH_TABLE_LAYOUT \
"pw_user char(32) NOT NULL, \
pw_domain varchar(223) NOT NULL,\
remote_ip char(18) not null,  \
timestamp bigint DEFAULT 0 NOT NULL, \
primary key (pw_user, pw_domain)"

#define SMALL_SITE 0
#define LARGE_SITE 1

char *vauth_munch_domain(char *);
int vauth_open();

int vauth_adddomain_size(char *, int);
int vauth_deldomain_size(char *, int);
int vauth_adduser_size(char *, char *, char *, char *, char *, int, int);
int vauth_deluser_size(char *, char *, int);
int vauth_vpasswd_size( char *, char *, char *, int, int);
int vauth_setquota_size( char *, char *, char *, int);
struct vqpasswd *vauth_getpw_size(char *, char *, int);
struct vqpasswd *vauth_user_size(char *, char *, char*, char *, int);
struct vqpasswd *vauth_getall_size(char *, int, int, int);
int vauth_setpw_size( struct vqpasswd *, char *, int);

#define LARGE_INSERT "insert into  %s \
( pw_name, pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell ) \
values \
( '%s', '%s', %d, 0, '%s', '%s', '%s' )"

#define SMALL_INSERT "insert into  %s \
( pw_name, pw_domain, pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell ) \
values \
( '%s', '%s', '%s', %d, 0, '%s', '%s', '%s' )"

#define LARGE_INSERT_CLEAR "insert into  %s \
( pw_name, pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell, pw_clear_passwd ) \
values \
( \"%s\", \"%s\", %d, 0, \"%s\", \"%s\", \"%s\", \"%s\" )"

#define SMALL_INSERT_CLEAR "insert into  %s \
( pw_name, pw_domain, pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell, pw_clear_passwd ) \
values \
( \"%s\", \"%s\", \"%s\", %d, 0, \"%s\", \"%s\", \"%s\", \"%s\" )"

#define LARGE_SELECT "select pw_name, pw_passwd, pw_uid, pw_gid, \
pw_gecos, pw_dir, pw_shell from %s where pw_name = '%s'"

#define SMALL_SELECT "select pw_name, pw_passwd, pw_uid, pw_gid, \
pw_gecos, pw_dir, pw_shell from %s where pw_name = '%s' and pw_domain = '%s'"

#define LARGE_SELECT_CLEAR "select pw_name, pw_passwd, pw_uid, pw_gid, \
pw_gecos, pw_dir, pw_shell, pw_clear_passwd from %s where pw_name = \"%s\""

#define SMALL_SELECT_CLEAR "select pw_name, pw_passwd, pw_uid, pw_gid, \
pw_gecos, pw_dir, pw_shell, pw_clear_passwd from %s where pw_name = \"%s\" \
and pw_domain = \"%s\""

#define LARGE_GETALL "select pw_name, pw_passwd, pw_uid, pw_gid, pw_gecos, \
pw_dir, pw_shell from %s"

#define SMALL_GETALL "select pw_name, pw_passwd, pw_uid, pw_gid, \
pw_gecos, pw_dir, pw_shell from %s where pw_domain = '%s'"

#define LARGE_SETPW "update %s set pw_passwd = '%s', \
pw_uid = %lu, pw_gid = %lu, pw_gecos = '%s', pw_dir = '%s', pw_shell = '%s' \
where pw_name = '%s'" 

#define SMALL_SETPW "update %s set pw_passwd = '%s', \
pw_uid = %lu, pw_gid = %lu, pw_gecos = '%s', pw_dir = '%s', pw_shell = '%s' \
where pw_name = '%s' and pw_domain = '%s'"

#define LARGE_SETPW_CLEAR "update %s set pw_passwd = \"%s\", \
pw_uid = %lu, pw_gid = %lu, pw_gecos = \"%s\", pw_dir = \"%s\", \
pw_shell = \"%s\", pw_clear_passwd = \"%s\" where pw_name = \"%s\""

#define SMALL_SETPW_CLEAR "update %s set pw_passwd = \"%s\", \
pw_uid = %lu, pw_gid = %lu, pw_gecos = \"%s\", pw_dir = \"%s\", \
pw_shell = \"%s\", pw_clear_passwd = \"%s\" \
where pw_name = \"%s\" and pw_domain = \"%s\""

#ifdef IP_ALIAS_DOMAINS
#define IP_ALIAS_TABLE_LAYOUT "ip_addr char(18) not null, domain varchar(255),  primary key(ip_addr)"
#endif

#define DIR_CONTROL_TABLE_LAYOUT "domain varchar(255) not null, cur_users int, \
level_cur int, level_max int, \
level_start0 int, level_start1 int, level_start2 int, \
level_end0 int, level_end1 int, level_end2 int, \
level_mod0 int, level_mod1 int, level_mod2 int, \
level_index0 int , level_index1 int, level_index2 int, the_dir varchar(255), \
primary key (domain) "

#define DIR_CONTROL_SELECT "cur_users, \
level_cur, level_max, \
level_start0, level_start1, level_start2, \
level_end0, level_end1, level_end2, \
level_mod0, level_mod1, level_mod2, \
level_index0, level_index1, level_index2, the_dir"

#define VALIAS_TABLE_LAYOUT "alias varchar(100) not null, \
domain varchar(100) not null, \
valias_line varchar(255) not null, index (alias, domain)"

#endif
