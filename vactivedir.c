/*
 * Copyright (C) 1999-2003 Inter7 Internet Technologies, Inc.
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
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <sys/time.h>
#include <time.h>
#include <utime.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include "config.h"
#include "vpopmail.h"
#include "vauth.h"
#include "file_lock.h"
#include "vactivedir.h"

#define MAX_BUFF 300
#define PACKET_SIZE 388

#define SMALL_BUFF 200
static char IUser[SMALL_BUFF];
static char IPass[SMALL_BUFF];
static char IGecos[SMALL_BUFF];
static char IDir[SMALL_BUFF];
static char IShell[SMALL_BUFF];
static char IClearPass[SMALL_BUFF];

char *dc_filename(char *domain, uid_t uid, gid_t gid);

typedef struct actdirvp {
  char cmd[16];
  char p1[16];
  char p2[16];
  char p3[16];
  char pw_name[32];
  char pw_domain[64];
  char pw_uid[16];
  char pw_gid[16];
  char pw_dir[160];
  char pw_shell[20];
  char pw_clear_passwd[16];
  char pw_gecos[48];
} actdirvp;

static int GetAllSock = -1;

int ad_open_conn()
{
 int sock;
 struct sockaddr_in sin;


  sock = socket(AF_INET,SOCK_STREAM,0);
  if ( sock == -1 ) return(-1);

  memset(&sin,0,sizeof(struct sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(ACTIVE_DIR_PORT);
  sin.sin_addr.s_addr = inet_addr(ACTIVE_DIR_IP);

  if (connect(sock,(struct sockaddr *)&sin,sizeof(struct sockaddr_in))==-1){
    close(sock);
    return(-1);
  }
  return(sock);
}

void inline ad_clean_one(char *inp, int len)
{
 int i;

  inp[len-1] = 0;
  for(i=len-2;i>=0;--i){
    if ( inp[i] == ' ' ) inp[i] = 0;
    else break;
  }
}

void ad_clean_packet(struct actdirvp *adir)
{
  /*memmove(adir,&adir->cmd[4], PACKET_SIZE-4);*/
  ad_clean_one(adir->cmd, 16);
  ad_clean_one(adir->p1, 16);
  ad_clean_one(adir->p2, 16);
  ad_clean_one(adir->p3, 16);
  ad_clean_one(adir->pw_name, 32);
  ad_clean_one(adir->pw_domain, 64);
  ad_clean_one(adir->pw_uid, 16);
  ad_clean_one(adir->pw_gid, 16);
  ad_clean_one(adir->pw_gecos, 48);
  ad_clean_one(adir->pw_dir, 160);
  ad_clean_one(adir->pw_shell, 20);
  ad_clean_one(adir->pw_clear_passwd, 16);
}

void ad_fill_vpw( struct vqpasswd *vpw, struct actdirvp *adir)
{
  vpw->pw_name   = IUser;
  vpw->pw_passwd = IPass;
  vpw->pw_gecos  = IGecos;
  vpw->pw_dir    = IDir;
  vpw->pw_shell  = IShell;
  vpw->pw_clear_passwd  = IClearPass;

  strncpy(vpw->pw_name, adir->pw_name, 32);
  memset(vpw->pw_passwd,0,sizeof(IPass));
  vpw->pw_uid = atoi(adir->pw_uid);
  vpw->pw_gid = atoi(adir->pw_gid);
  strncpy(vpw->pw_gecos, adir->pw_gecos, 48);
  strncpy(vpw->pw_dir, adir->pw_dir, 160);
  strncpy(vpw->pw_shell, adir->pw_shell, 20);
  strncpy(vpw->pw_clear_passwd, adir->pw_clear_passwd, 16);
}

void ad_print_packet(struct actdirvp *adir)
{
  printf("cmd: |%-16s|\n", adir->cmd);
  printf("p1: |%-16s|\n", adir->p1);
  printf("p2: |%-16s|\n", adir->p2);
  printf("p3: |%-16s|\n", adir->p3);
  printf("name: |%-32s|\n", adir->pw_name);
  printf("domain: |%-32s|\n", adir->pw_domain);
  printf("gecos: |%-48s|\n", adir->pw_gecos);
  printf("uid: |%-16s|\n", adir->pw_uid);
  printf("gid: |%-16s|\n", adir->pw_gid);
  printf("dir: |%-160s|\n", adir->pw_dir);
  printf("shell: |%-20s|\n", adir->pw_shell);
  printf("clear passwd: |%-16s|\n", adir->pw_clear_passwd);


}

struct vqpasswd *vauth_getpw(char *user, char *domain)
{
 static struct vqpasswd vpw;
 static struct actdirvp adir;
 int sock;

  if ( (sock=ad_open_conn())==-1){
    printf("could not connect\n");
    return(NULL);
  }
  memset(&adir,' ',sizeof(struct actdirvp));
  memcpy( adir.cmd, "select", 6);
  memcpy( adir.pw_name, user, strlen(user));
  memcpy( adir.pw_domain, domain, strlen(domain));

  if ( write(sock,&adir, sizeof(struct actdirvp))<0){
    close(sock);
    printf("vauth_getpw: write failed\n");
    return(NULL);
  }

  if ( read(sock,&adir, sizeof(struct actdirvp))<0) {
    close(sock);
    printf("vauth_getpw: read failed\n");
    return(NULL);
  }
  ad_clean_packet(&adir);
  close(sock);

  if ( strncmp(adir.p1,"yes",3) != 0 ) return(NULL); 
  
  ad_fill_vpw(&vpw,&adir);
  return(&vpw);
}


struct vqpasswd *vauth_getall(char *domain, int first, int sortit)
{
 static struct vqpasswd vpw;
 static struct actdirvp adir;
 char foob[4];
 int size;

  if ( first == 1 ) {
    if ( GetAllSock != -1 ) close(GetAllSock);

    if ( (GetAllSock=ad_open_conn())==-1){
      printf("could not connect\n");
      return(NULL);
    }
    memset(&adir,' ',sizeof(struct actdirvp));
    memcpy( adir.cmd, "getall", 6);
    memcpy( adir.pw_domain, domain, strlen(domain));
  
    if ( write(GetAllSock,&adir, sizeof(struct actdirvp))<0){
      close(GetAllSock);
      GetAllSock = -1;
      return(NULL);
    }
  }
  if ( GetAllSock == -1 ) return(NULL);
  
  memset(&adir,' ',sizeof(struct actdirvp));
  if ( (size=read(GetAllSock,&adir, sizeof(struct actdirvp)))<0) {
    close(GetAllSock);
    GetAllSock = -1;
    return(NULL);
  }
  if ( first == 1 ) read(GetAllSock, foob,4);
  ad_clean_packet(&adir);

  if ( strncmp(adir.p1,"yes",3) != 0 ) {
    close(GetAllSock);
    GetAllSock = -1;
    return(NULL); 
  }
  
  ad_fill_vpw(&vpw,&adir);
  return(&vpw);
}

void vauth_end_getall()
{
  if ( GetAllSock !=  -1 ) {
    close(GetAllSock);
    GetAllSock = -1;
  }
}

int vauth_adduser(char *user, char *domain, char *pass, char *gecos, 
                  char *dir, int apop )
{
 static struct actdirvp adir;
 int sock;
 char tmpbuf[160];
 char dom_dir[160];

  if ( (sock=ad_open_conn())==-1){
    printf("could not connect\n");
    return(-1);
  }
  memset(&adir,' ',sizeof(struct actdirvp));
  memcpy( adir.cmd, "create", 6);
  memcpy( adir.pw_name, user, strlen(user));
  memcpy( adir.pw_domain, domain, strlen(domain));
  memcpy( adir.pw_clear_passwd, pass, strlen(pass));
  memcpy( adir.pw_gecos, gecos, strlen(gecos));
  if ( apop == USE_POP ) memcpy( adir.pw_uid, "1", 1);
  else memcpy( adir.pw_uid, "2", 1);
  memcpy( adir.pw_gid, "0", 1);

  vget_assign(domain, dom_dir, 160, NULL, NULL);
  if ( strlen(dir) > 0 ) {
    snprintf(tmpbuf,160, "%s/%s/%s", dom_dir, dir, user);
  } else {
    snprintf(tmpbuf, 160, "%s/%s", dom_dir, user);
  }

  memcpy( adir.pw_dir, tmpbuf, strlen(tmpbuf));
#ifdef HARD_QUOTA
  memcpy( adir.pw_shell, HARD_QUOTA, strlen(HARD_QUOTA));
#else
  memcpy( adir.pw_shell, "NOQUOTA", 7);
#endif


  /*ad_print_packet(&adir);*/
  if ( write(sock,&adir, sizeof(struct actdirvp))<0){
    close(sock);
    printf("write failed\n");
    return(-1);
  }

  if ( read(sock,&adir, sizeof(struct actdirvp))<0) {
    close(sock);
    printf("read failed\n");
    return(-1);
  }
  ad_clean_packet(&adir);
  close(sock);

  if ( strncmp(adir.p1,"yes",3) != 0 ) return(-1); 
  return(0);
}

int vauth_adddomain( char *domain )
{
  return(0);
}

int vauth_deldomain( char *domain )
{
  return(0);
}

int vauth_deluser( char *user, char *domain )
{
 static struct actdirvp adir;
 int sock;

  if ( (sock=ad_open_conn())==-1){
    printf("could not connect\n");
    return(-1);
  }
  memset(&adir,' ',sizeof(struct actdirvp));
  memcpy( adir.cmd, "delete", 6);
  memcpy( adir.pw_name, user, strlen(user));
  memcpy( adir.pw_domain, domain, strlen(domain));

  if ( write(sock,&adir, sizeof(struct actdirvp))<0){
    close(sock);
    printf("write failed\n");
    return(-1);
  }

  if ( read(sock,&adir, sizeof(struct actdirvp))<0) {
    close(sock);
    printf("read failed\n");
    return(-1);
  }
  ad_clean_packet(&adir);
  close(sock);

  if ( strncmp(adir.p1,"yes",3) != 0 ) return(-1); 
  return(0);
}

/* Utility function to set the users quota
 *
 * Calls underlying vauth_getpw and vauth_setpw
 * to actually change the users information
 */
int vauth_setquota( char *username, char *domain, char *quota)
{
 struct vqpasswd *vpw;

  vpw = vauth_getpw( username, domain );
  if ( vpw==NULL ) return(VA_USER_DOES_NOT_EXIST);
  vpw->pw_shell = quota;
  return(vauth_setpw(vpw,domain));
}

int vauth_setpw( struct vqpasswd *vpw, char *domain ) 
{
 static struct actdirvp adir;
 int sock;
 char tmpbuf[160];

  if ( (sock=ad_open_conn())==-1){
    printf("could not connect\n");
    return(-1);
  }
  memset(&adir,' ',sizeof(struct actdirvp));
  memcpy( adir.cmd, "update", 6);
  memcpy( adir.pw_name, vpw->pw_name, strlen(vpw->pw_name));
  memcpy( adir.pw_domain, domain, strlen(domain));
  memcpy( adir.pw_gecos, vpw->pw_gecos, strlen(vpw->pw_gecos));

  snprintf(tmpbuf,16,"%d", vpw->pw_uid);
  memcpy( adir.pw_uid, tmpbuf, strlen(tmpbuf));

  snprintf(tmpbuf,16,"%d", vpw->pw_gid);
  memcpy( adir.pw_gid, tmpbuf, strlen(tmpbuf));

  memcpy( adir.pw_dir, vpw->pw_dir, strlen(vpw->pw_dir));
  memcpy( adir.pw_shell, vpw->pw_shell, strlen(vpw->pw_shell));
  memcpy( adir.pw_clear_passwd, vpw->pw_clear_passwd, 
          strlen(vpw->pw_clear_passwd));

  if ( write(sock,&adir, sizeof(struct actdirvp))<0){
    close(sock);
    printf("write failed\n");
    return(-1);
  }

  if ( read(sock,&adir, sizeof(struct actdirvp))<0) {
    close(sock);
    printf("read failed\n");
    return(-1);
  }
  ad_clean_packet(&adir);
  close(sock);

  if ( strncmp(adir.p1,"yes",3) != 0 ) return(-1); 
  return(0);
}


void vclose() { }

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

  snprint(file2, 156, "%s/%s.%d", VPOPMAILDIR, IP_ALIAS_MAP_FILE, getpid());
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

    if ( strcmp(ip, ip_f) == 0 && strcmp(domain,domain_f) == 0) continue;
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

int vread_dir_control(vdir_type *vdir, char *domain, uid_t uid, gid_t gid)
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

int vwrite_dir_control(vdir_type *vdir, char *domain, uid_t uid, gid_t gid)
{ 
 FILE *fs;
 char dir_control_file[MAX_DIR_NAME];
 char dir_control_tmp_file[MAX_DIR_NAME];

  strncpy(dir_control_file,dc_filename(domain, uid, gid),MAX_DIR_NAME);
  snprintf(dir_control_tmp_file, MAX_DIR_NAME, 
        "%s.%d", dir_control_file, getpid());

  if ( (fs = fopen(dir_control_tmp_file, "w+")) == NULL ) return(-1);

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
  strncat(dir_control_file,"/.dir-control", MAX_DIR_NAME);
  return(unlink(dir_control_file));
}

int vset_lastauth(char *user, char *domain, char *remoteip )
{
#ifdef ENABLE_AUTH_LOGGING
 char *tmpbuf;
 FILE *fs;
 struct vqpasswd *vpw;
 uid_t uid;
 gid_t gid;

  if( (vpw = vauth_getpw( user, domain )) == NULL) return(0);

  tmpbuf = malloc(MAX_BUFF);
  snprintf(tmpbuf, MAX_BUFF, "%s/lastauth", vpw->pw_dir);
  if ( (fs = fopen(tmpbuf,"w+")) == NULL ) {
    free(tmpbuf);
    return(-1);
  }
  fprintf(fs, "%s", remoteip);
  fclose(fs);

  vget_assign(domain,NULL,0,&uid,&gid);
  chown(tmpbuf,uid,gid);
  free(tmpbuf);
#endif
  return(0);
}

time_t vget_lastauth( struct vqpasswd *pw, char *domain)
{
#ifdef ENABLE_AUTH_LOGGING
 char *tmpbuf;
 struct stat mystatbuf;

  tmpbuf = malloc(MAX_BUFF);
  snprintf(tmpbuf, MAX_BUFF, "%s/lastauth", pw->pw_dir);
  if ( stat(tmpbuf,&mystatbuf) == -1 ) {
    free(tmpbuf);
    return(0);
  }
  free(tmpbuf);
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

char *dc_filename(char *domain, uid_t uid, gid_t gid)
{
 static char dir_control_file[MAX_DIR_NAME];
 struct passwd *pw;

  /* if we are lucky the domain is in the assign file */
  if ( vget_assign(domain,dir_control_file,MAX_DIR_NAME,NULL,NULL)!=NULL ) { 
    strncat(dir_control_file, "/.dir-control", MAX_DIR_NAME);

  /* it isn't in the assign file so we have to get it from /etc/passwd */
  } else {
      
    /* save some time if this is the vpopmail user */
    if ( uid == VPOPMAILUID ) {
      strncpy(dir_control_file, VPOPMAILDIR, MAX_DIR_NAME);

    /* for other users, look them up in /etc/passwd */
    } else if ( (pw=getpwuid(uid))!=NULL ) {
      strncpy(dir_control_file, pw->pw_dir, MAX_DIR_NAME);

      /* all else fails return a blank string */
    } else {
      return("");
    }

    /* stick on the rest of the path */
    strncat(dir_control_file, "/" DOMAINS_DIR "/.dir-control", MAX_DIR_NAME); 
  }
  return(dir_control_file);
}


int vauth_crypt(char *user,char *domain,char *clear_pass,struct vqpasswd *vpw)
{
 static struct actdirvp adir;
 int sock;

  if ( (sock=ad_open_conn())==-1){
    printf("could not connect\n");
    return(-1);
  }
  memset(&adir,' ',sizeof(struct actdirvp));
  memcpy( adir.cmd, "auth", 4);
  memcpy( adir.pw_name, user, strlen(user));
  memcpy( adir.pw_domain, domain, strlen(domain));
  memcpy( adir.pw_clear_passwd, clear_pass, strlen(clear_pass));

  if ( write(sock,&adir, sizeof(struct actdirvp))<0){
    close(sock);
    printf("write failed\n");
    return(-1);
  }

  if ( read(sock,&adir, sizeof(struct actdirvp))<0) {
    close(sock);
    printf("read failed\n");
    return(-1);
  }
  ad_clean_packet(&adir);
  /*ad_print_packet(&adir);*/

  close(sock);
  if ( strncmp(adir.p1,"yes",3) == 0 ) return(0); 
  return(-1);
}
