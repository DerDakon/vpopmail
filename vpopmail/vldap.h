/*
 * Copyright (C) 2000-2002 Inter7 Internet Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License  
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

int ldapversion = 3;

void *safe_malloc (size_t siz);
char *safe_strdup (const char *s);
void safe_free (void **p);
int ldap_connect ();
int compose_dn (char **dn, char *domain);

#ifndef VPOPMAIL_LDAP_H
#define VPOPMAIL_LDAP_H

#undef OLD_VLDAP

#define VLDAP_SERVER "localhost"
#define VLDAP_PORT LDAP_PORT
#define VLDAP_USER "cn=Manager, o=vpop"
#define VLDAP_PASSWORD "proba"
#define MAX_BUFF 500

#ifdef OLD_VLDAP
   #define VLDAP_BASEDN "ou=Subs, o=vpop"
#else
   #define VLDAP_BASEDN "ou=%s, o=vpop"
#endif

static char *vldap_attrs[] = {
  "name",
  "uid",
  "qmailGID",
  "qmailUID",
  "qmaildomain",
  "userPassword",
  "mailQuota",
  "mailMessageStore",  
#ifdef CLEAR_PASS
  "clearPassword",
#endif
NULL
};
#endif
