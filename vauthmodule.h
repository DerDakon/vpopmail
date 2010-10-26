/*
   $Id$
   Copyright (C) 2009 Inter7 Internet Technologies, Inc.
*/

#ifndef __VAUTHMODULE_H_
   #define __VAUTHMODULE_H_

#include "vauth.h"

#ifndef VAUTH_MODULE

int (*vauth_adddomain)(char *);
int (*vauth_deldomain)(char *);
int (*vauth_adduser)(char *username, char *domain, char *passwd, char *gecos, char * dir, int apop);
int (*vauth_crypt)(char *user,char *domain,char *clear_pass,struct vqpasswd *vpw);
int (*vauth_deluser)(char *, char *);
int (*vauth_setquota)( char *, char *, char *);
struct vqpasswd *(*vauth_getpw)(char *, char *);
int (*vauth_setpw)(struct vqpasswd *, char *);
struct vqpasswd *(*vauth_getall)(char *, int, int);
void (*vauth_end_getall)();
int (*vmkpasswd)( char *domain );
int (*vread_dir_control)(vdir_type *vdir, char *domain, uid_t uid, gid_t gid );
int (*vwrite_dir_control)(vdir_type *vdir, char *domain, uid_t uid, gid_t gid);
int (*vdel_dir_control)(char *domain);
int (*vset_lastauth)( char *user, char *domain, char *remoteip);
time_t (*vget_lastauth)( struct vqpasswd *pw, char *domain);
char *(*vget_lastauthip)( struct vqpasswd *pw, char *domain);
char *(*valias_select)( char *alias, char *domain );
char *(*valias_select_next)();
char *(*valias_select_all)( char *alias, char *domain );
char *(*valias_select_all_next)(char *alias);
char *(*valias_select_names)(char *);
char *(*valias_select_names_next)();
char *(*valias_select_names_end)();
int (*valias_insert)( char *alias, char *domain, char *alias_line);
int (*valias_remove)( char *alias, char *domain, char *alias_line);
int (*valias_delete)( char *alias, char *domain);
int (*valias_delete_domain)( char *domain);
int (*vget_ip_map)( char *ip, char *domain, int domain_size);
int (*vadd_ip_map)( char *ip, char *domain);
int (*vdel_ip_map)( char *ip, char *domain); 
int (*vshow_ip_map)( int first, char *ip, char *domain);

#endif
#endif
