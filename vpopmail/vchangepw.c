/*
 * $Id: vchangepw.c,v 1.4 2004-12-28 00:31:05 rwidmer Exp $
 * Modified version of vpasswd created by Rolf Eike Beer, November 2003
 *
 * Usage Note: 
 * The binary "vchangepw" is added. I set up another 
 * user account with this binary as shell and uid/gid 
 * identical to vpopmail. Now users can ssh to the box 
 * as this user and change the password remote without 
 * asking me. It's as secure as everything else when the 
 * login is only allowed with ssh, so everything is 
 * crypted.
 *
 * If you don't create an account as above, you will need to change
 * permissions and ownership on vchangepw to suid vpopmail.
 *
 * Copyright (C) 1999,2001 Inter7 Internet Technologies, Inc.
 * Copyright (C) 2003 Rolf Eike Beer
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
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
#include <string.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include "config.h"
#include "vpopmail.h"
#include "vauth.h"

int main(int argc, char *argv[])
{
	int i;
	uid_t pw_uid;
	gid_t pw_gid;
	struct vqpasswd *vpw = NULL;
	char Email[MAX_BUFF];
	char User[MAX_BUFF];
	char Domain[MAX_BUFF];
	char Passwd[MAX_BUFF];
	char OldPasswd[MAX_BUFF];

    if( vauth_open( 1 )) {
        vexiterror( stderr, "Initial open." );
    }

	memset(Email, 0, MAX_BUFF);
	memset(Passwd, 0, MAX_BUFF);
	memset(Domain, 0, MAX_BUFF);
	memset(User, 0, MAX_BUFF);

	printf("Please enter the email address: ");

	fgets(Email, MAX_BUFF, stdin);
	i = strlen(Email);
	if (i)
		Email[i-1]=0;
	
	printf("%s\n", Email);

        if ( (i = parse_email( Email, User, Domain, MAX_BUFF)) != 0 ) {
            printf("Error: %s\n", verror(i));
            vexit(i);
        }

	strncpy(OldPasswd, getpass("Enter old password: "), MAX_BUFF);

	openlog("vchangepw", 0, LOG_AUTH);

	if ( (vpw = vauth_getpw(User, Domain)) != NULL ) {
		vget_assign(Domain,NULL,0,&pw_uid,&pw_gid);
		if ( strcmp(crypt(OldPasswd,vpw->pw_passwd),vpw->pw_passwd) != 0 ) {
			printf("Error: authentication failed!\n");
			syslog(LOG_NOTICE, "Wrong password for user <%s>\n", Email);
			closelog();
			vexit(3);
		}
	}

	strncpy( Passwd, vgetpasswd(Email), MAX_BUFF);

	if ( (i=vpasswd( User, Domain, Passwd, USE_POP )) != 0 ) {
		printf("Error: %s\n", verror(i));
		syslog(LOG_NOTICE, "Error changing users password! User <%s>, message: ""%s""\n", Email,
			verror(i));
		vexit(i);
	} else {
		printf("Password successfully changed.\n");
		syslog(LOG_DEBUG, "User <%s> changed password\n", Email);
	}
	closelog();
	return vexit(i);
}
