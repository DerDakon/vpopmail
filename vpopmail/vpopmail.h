/*
 * $Id: vpopmail.h,v 1.5 2003-12-17 03:13:40 tomcollins Exp $
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
#ifndef VPOPMAIL_VPOPMAIL_H
#define VPOPMAIL_VPOPMAIL_H

#define DEFAULT_DOMAIN default_domain()

/* max field sizes */
#define MAX_PW_NAME         32
#define MAX_PW_DOMAIN       64
#define MAX_PW_PASS         40
#define MAX_PW_GECOS        48
#define MAX_PW_CLEAR_PASSWD 16
#define MAX_PW_DIR         160
#define MAX_PW_QUOTA        20
#define MAX_ALIAS_LINE     160

#define ATCHARS "@%/"
#define BOUNCE_ALL "bounce-no-mailbox"
#define DELETE_ALL "delete"

/* modes for vpopmail dirs, files and qmail files */
#define VPOPMAIL_UMASK          0077
#define VPOPMAIL_TCPRULES_UMASK 0022
#define VPOPMAIL_DIR_MODE       0750
#define VPOPMAIL_QMAIL_MODE S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH

#define USE_POP      0x00
#define USE_APOP     0x01

/* error return codes */
#define VA_SUCCESS                        0
#define VA_ILLEGAL_USERNAME              -1
#define VA_USERNAME_EXISTS               -2
#define VA_BAD_DIR                       -3
#define VA_BAD_U_DIR                     -4
#define VA_BAD_D_DIR                     -5
#define VA_BAD_V_DIR                     -6
#define VA_EXIST_U_DIR                   -7
#define VA_BAD_U_DIR2                    -8
#define VA_SUBDIR_CREATION               -9
#define VA_USER_DOES_NOT_EXIST          -10
#define VA_DOMAIN_DOES_NOT_EXIST        -11
#define VA_INVALID_DOMAIN_NAME          -12
#define VA_DOMAIN_ALREADY_EXISTS        -13
#define VA_COULD_NOT_MAKE_DOMAIN_DIR    -14
#define VA_COULD_NOT_OPEN_QMAIL_DEFAULT -15
#define VA_CAN_NOT_MAKE_DOMAINS_DIR     -16
#define VA_COULD_NOT_UPDATE_FILE        -17
#define VA_CRYPT_FAILED                 -18
#define VA_COULD_NOT_OPEN_DOT_QMAIL     -19
#define VA_BAD_CHAR                     -20
#define VA_SQWEBMAIL_PASS_FAIL          -21
#define VA_BAD_UID                      -22
#define VA_NO_AUTH_CONNECTION           -23
#define VA_MEMORY_ALLOC_ERR             -24
#define VA_USER_NAME_TOO_LONG           -25
#define VA_DOMAIN_NAME_TOO_LONG         -26
#define VA_PASSWD_TOO_LONG              -27
#define VA_GECOS_TOO_LONG               -28
#define VA_QUOTA_TOO_LONG               -29
#define VA_DIR_TOO_LONG                 -30
#define VA_CLEAR_PASSWD_TOO_LONG        -31
#define VA_ALIAS_LINE_TOO_LONG          -32
#define VA_NULL_POINTER                 -33
#define VA_INVALID_EMAIL_CHAR           -34
#define VA_PARSE_ERROR                  -35
#define VA_CANNOT_READ_LIMITS           -36

/* gid flags */
#define NO_PASSWD_CHNG 0x01
#define NO_POP         0x02
#define NO_WEBMAIL     0x04
#define NO_IMAP        0x08
#define BOUNCE_MAIL    0x10
#define NO_RELAY       0x20
#define NO_DIALUP      0x40
#define V_USER0       0x080
#define V_USER1       0x100
#define V_USER2       0x200
#define V_USER3       0x400
#define NO_SMTP       0x800
#define QA_ADMIN     0x1000
#define V_OVERRIDE   0x2000

extern int OptimizeAddDomain;
extern int NoMakeIndex;
extern int verrori;

/* functions */
int vadddomain( char *domain, char *dir, uid_t uid, gid_t gid);
int vdeldomain( char *);
int vadduser( char *, char *, char *, char *, int);
int vdeluser( char *, char *);
int vpasswd( char *, char *, char *, int);
int vsetuserquota( char *, char *, char * );
int vexit(int err);

char randltr(void);
int mkpasswd3( char *, char *, int);
char *vgetpasswd( char *);
int vdelfiles( char *);
int add_domain_assign( char *alias_domain, char *real_domain, 
                       char *dir, uid_t uid, gid_t gid);
int del_control( char *);
int del_domain_assign( char *alias_domain, char *real_domain,
                       char *dir, uid_t uid, gid_t gid);
int remove_line( char *, char *);
int r_chown( char *, uid_t, gid_t);
int signal_process( char *, int );
int update_newu();
int parse_email( char *, char *, char *, int);
int add_user_assign( char *, char *);
int del_user_assign( char *);
void lowerit( char *);
char *crypt();
int update_file(char *, char *);
int count_rcpthosts();
int compile_morercpthosts();
char *make_user_dir(char *username, char *domain, uid_t uid, gid_t gid);
int r_mkdir(char *, uid_t uid, gid_t gid);
struct vqpasswd *vgetent(FILE *);
int pw_comp(char *, char *, char *, int);
char *default_domain();
void vset_default_domain( char *);
int vopen_smtp_relay();	
void vupdate_rules(int);
void vclear_open_smtp(time_t, time_t);
char *verror(int);
int vadddotqmail(char *alias, char *domain,... ); 
int vdeldotqmail( char *alias, char *domain);
int vget_real_domain(char *domain, int len );
char *vget_assign(char *domain, char *dir, int dir_len, uid_t *uid, gid_t *gid);
struct vqpasswd *vauth_user(char *user, char *domain, char *password, char *apop);
int vmake_maildir(char *domain, char *dir);
int vsqwebmail_pass( char *dir, char *crypted, uid_t uid, gid_t gid );
int open_smtp_relay();
unsigned  long tcprules_open();
int vfd_copy(int,int);
int vfd_move(int,int);
int update_rules();
char *vversion(char *);
void remove_maildirsize(char *dir);
int vcheck_vqpw(struct vqpasswd *inpw, char *domain);
char *vgen_pass(int len);
char *vrandom_pass (char *buffer, int len);
int vvalidchar( char inchar );
int is_username_valid( char *user );
int is_domain_valid( char *domain );
int vaddaliasdomain( char *alias_domain, char *real_domain);
char *format_maildirquota(const char *q);
char *date_header();
char *get_remote_ip();

#ifdef APOP
char *dec2hex(unsigned char *);
#endif


#endif
