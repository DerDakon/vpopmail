/*
 * $Id$
 * Copyright (C) 1999-2009 Inter7 Internet Technologies, Inc.
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
 *
 */

#include <stdio.h>
#include <string.h>
#include "quota.h"
#include "client.h"
#include "storage.h"
#include "vlimits.h"
#include "vauth.h"
#include "vpopmail.h"

/*
   Looks up a user and checks it's quota and it's
   domain's quota
*/

int quota_check(const char *email)
{
   struct vqpasswd *pw = NULL;

   /*
	  Look up the user
   */

   pw = vauth_getpw_long(email);
   if (pw == NULL)
	  return 0;

   /*
	  Return quota check
   */

   return quota_compare(email, pw->pw_shell);
}

/*
   Compares if a user is over a provided quota, or
   if the domain is over it's configured quota
*/

int quota_compare(const char *email, const char *quota)
{
   int ret = 0;
   void *handle = NULL;
   const char *p = NULL;
   struct vlimits vl;
   storage_t squota = 0, cquota = 0, usage = 0, count = 0;

   if ((email == NULL) || (quota == NULL))
	  return 0;

   handle = NULL;

   /*
	  Convert quota string to integers
   */

   quota_mtos(quota, &squota, &cquota);

   /*
	  Connect to the usage daemon
   */

   if ((squota) || (cquota)) {
	  handle = client_connect();
	  if (handle == NULL)
		 return 0;

	  /*
		 Get user usage
	  */

	  ret = client_query(handle, email, strlen(email), &usage, &count);

	  /*
		 Query succeeded and data was available
	  */

	  if ((ret) && (usage != -1)) {
		 if ((usage >= squota) || (count >= cquota)) {
			client_close(handle);
			return 1;
		 }
	  }
   }

   /*
	  Get domain
   */

   for (p = email; *p; p++) {
	  if (*p == '@')
		 break;
   }

   /*
	  This function does not support defaultdomain
	  and never should
   */

   if (!(*p)) {
	  if (handle)
		 client_close(handle);

	  return 0;
   }

   ret = vget_limits((p + 1), &vl);
   
   /*
	  Failed to get limits
   */

   if (ret) {
	  if (handle)
		 client_close(handle);

	  return 0;
   }

   /*
	  Connect to the daemon if we didn't already for the user check
   */

   if (handle == NULL) {
	  handle = client_connect();
	  if (handle == NULL)
		 return 0;
   }

   ret = client_query(handle, p, strlen(p), &usage, &count);
   client_close(handle);

   /*
	  Query succeeded and data available
   */

   if ((ret) && (usage != -1)) {
	  if ((usage >= vl.diskquota) || (count >= vl.maxmsgcount))
		 return 1;
   }

   return 0;
}

/*
   Converts a Maildir++ quota to storage_t values
   Does not perform full syntax checking on quota format
*/

int quota_mtos(const char *quota, storage_t *size, storage_t *count)
{
   storage_t ts = 0;
   const char *h = NULL, *t = NULL;

   if (quota == NULL)
	  return 0;

   /*
	  Set default values
   */

   if (size != NULL)
	  *size = 0;

   if (count != NULL)
	  *count = 0;

   /*
	  Parse out seperate Maildir++ parts
   */

   h = t = quota;

   while(1) {
	  if ((*h == ',') || (!(*h))) {
		 switch(*(h - 1)) {
			case 'S':
			   if (size) {
				  ts = strtoll(t, NULL, 10);
				  if (ts != -1)
					 *size = ts;

				  size = NULL;
			   }

			   break;

			case 'C':
			   if (count) {
				  ts = strtoll(t, NULL, 10);
				  if (ts != -1)
					 *count = ts;

				  count = NULL;
			   }

			   break;

			default:
			   /*
				  Default is type S
			   */

			   if ((!(*h)) && (size)) {
				  ts = strtoll(t, NULL, 10);
				  if (ts != -1)
					 *size = ts;

				  size = NULL;
			   }

			   /*
				  Unknown type
			   */

			   break;
		 }

		 if (!(*h))
			break;

		 while(*h == ',')
			h++;

		 t = h;
	  }

	  else
		 h++;
   }

   return 1;
}
