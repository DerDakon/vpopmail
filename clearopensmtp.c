/*
 * opensmtp
 * part of the vpopmail package
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include "config.h"
#include "vpopmail.h"
#include "vauth.h"

#ifdef POP_AUTH_OPEN_RELAY

#ifndef USE_MYSQL
#define MAX_BUFF 200
static char TmpBuf1[MAX_BUFF];
static char TmpBuf2[MAX_BUFF];
#endif

int main()
{
#ifndef USE_MYSQL
 FILE *fs;
 FILE *fs1;
 char *tmpstr;
 time_t file_time;
#endif
 time_t mytime;
 time_t clear_minutes;

	clear_minutes = RELAY_CLEAR_MINUTES * 60;
	mytime = time(NULL);

#ifdef USE_MYSQL
	vclear_open_smtp(clear_minutes, mytime);
#else
	fs = fopen(OPEN_SMTP_CUR_FILE, "r+");
	if ( fs != NULL ) {

		fs1 = fopen(OPEN_SMTP_TMP_FILE, "w+");
		if ( fs1 == NULL ) {
			return(0);
		}

		while ( fgets(TmpBuf1, MAX_BUFF, fs ) != NULL ) {
			strncpy(TmpBuf2, TmpBuf1, MAX_BUFF);
			tmpstr = strtok( TmpBuf2, "\t");
			tmpstr = strtok( NULL, "\t");
			if ( tmpstr != NULL ) {
				file_time = atoi(tmpstr);
				if ( file_time + clear_minutes > mytime) {
					fputs(TmpBuf1, fs1);
				}
			}
		}
		fclose(fs);
		fclose(fs1);

		rename(OPEN_SMTP_TMP_FILE, OPEN_SMTP_CUR_FILE);
		chown(OPEN_SMTP_CUR_FILE,VPOPMAILUID,VPOPMAILGID);
	}
#endif

	update_rules();
	return(vexit(0));
}
#else
int main()
{
	printf("vpopmail not configure with --enable-roaming-users=y\n");
	return(vexit(0));
}
#endif
