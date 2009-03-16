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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
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
   int ret = 0;
   struct vqpasswd *pw = NULL;

   /*
	  Look up the user
   */

   pw = vauth_getpw_long(email);
   if (pw == NULL)
	  return 0;

   /*
	  Do quota check
   */

   ret = quota_compare(email, pw->pw_shell);

   /*
	  Domain is over quota
   */

   if (ret == -2)
	  return 1;

   /*
	  Deliver quotawarn
   */

   return 1;
}

/*
   Looks up a domain quota and checks it's limits
*/

int quota_check_domain(const char *domain)
{
   int ret = 0;
   char b[256] = { 0 };
   struct vlimits vl;
   storage_t bytes = 0, count = 0;

   if (domain == NULL)
	  return 0;

   /*
	  Get domain limits
   */
   
   ret = vget_limits(domain, &vl);
   if (ret)
	  return 0;

   /*
	  Format domain query
   */

   ret = strlen(domain);
   if (ret >= (sizeof(b) - 2))
	  return 0;

   *b = '@';
   memcpy((b + 1), domain, ret);
   *(b + ret + 1) = '\0';

   /*
	  Query
   */

   ret = client_query_quick(b, &bytes, &count);
   if ((!ret) || (bytes == -1))
	  return 0;

   /*
	  Compare
   */

   if (((vl.diskquota) && (bytes >= vl.diskquota)) || ((vl.maxmsgcount) && ((count >= vl.maxmsgcount))))
	  return 1;

   return 0;
}

/*
   Compares if a user is over a provided quota, or
   if the domain is over it's configured quota

   Returns 0 if not over quota or no user record
   Returns 1 if over by user quota
   Returns 2 if over by domain quota
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
		 if (((squota) && (usage >= squota)) || ((cquota) && ((count >= cquota)))) {
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
	  if (((vl.diskquota) && (usage >= vl.diskquota)) || (((vl.maxmsgcount) && (count >= vl.maxmsgcount))))
		 return 2;
   }

   return 0;
}

/*
   Queries the usage server for usage values
   Can return domain or user usage

   Returns 1 if query successful and data was available for the record
*/

int quota_get_usage(const char *record, storage_t *bytes, storage_t *count)
{
   int ret = 0;

   if ((record == NULL) || (bytes == NULL) || (count == NULL))
	  return 0;

   ret = client_query_quick(record, bytes, count);
   if ((!ret) || (*bytes == -1)) {
	  *bytes = *count = 0;
	  return 0;
   }

   return 1;
}

/*
   Returns record quota usage percentage
*/

int quota_usage(const char *record, const char *quota)
{
   int ret = 0;
   storage_t squota = 0, cquota = 0, bytes = 0, count = 0;

   /*
	  Get usage
   */

   ret = quota_get_usage(record, &bytes, &count);
   if (!ret)
	  return 0;

   /*
	  Parse quota
   */

   quota_mtos(quota, &squota, &cquota);

   /*
	  Return percentage
   */

   return quota_percent(bytes, count, squota, cquota);
}

/*
   Returns percentage of highest usage between bytes and message count
*/

int quota_percent(storage_t bytes, storage_t count, storage_t squota, storage_t cquota)
{
   storage_t sp = 0, cp = 0;

   sp = cp = 0;

   if (squota) {
	  sp = (int)((float)((float)bytes / (float)squota) * (float)100);

	  if (sp > 100)
		 sp = 100;

	  if (sp < 0)
		 sp = 0;
   }

   if (cquota) {
	  cp = (int)((float)((float)count / (float)cquota) * (float)100);

	  if (cp > 100)
		 cp = 100;

	  if (cp < 0)
		 cp = 0;
   }

   if (cp > sp)
	  return cp;

   return sp;
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

/*
   Returns if the quota system should warn the user
   Returns 1 if yes, 0 if no or error
*/

int quota_should_warn(struct vqpasswd *pw)
{
   time_t tm = 0;
   int ret = 0;
   struct stat st;
   char b[255] = { 0 };

   /*
	  Check used parameters
   */

   if (pw == NULL)
	  return 0;

   if (pw->pw_dir == NULL)
	  return 0;

   tm = time(NULL);

   memset(b, 0, sizeof(b));
   snprintf(b, sizeof(b), "%s/quotawarn", pw->pw_dir);

   /*
	  Check filetime
   */

   ret = stat(b, &st);
   if (ret == -1)
	  return 0;

   if ((st.st_mtime + 86400) > tm)
	  return 0;

   return 1;
}
