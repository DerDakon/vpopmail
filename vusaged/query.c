/*
   $Id$

   * Copyright (C) 2009 Inter7 Internet Technologies, Inc.
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
#ifdef ASSERT_DEBUG
   #include <assert.h>
#endif
#include "storage.h"
#include "packet.h"
#include "user.h"
#include "query.h"
#include "queue.h"

/*
   Parse a single query from the network
*/

int query_parse(void *handle, char *data, int len)
{
   int ret = 0;
   char *p = NULL;
   storage_t uusage = 0, dusage = 0;

#ifdef ASSERT_DEBUG
   assert(handle != NULL);
   assert(data != NULL);
#endif

#ifdef QUERY_DEBUG
   printf("query: %s\n", data);
#endif

   /*
	  Default response 'Not monitored'
   */

   uusage = dusage = -1;

   /*
	  Get user usage
   */

   uusage = user_get_usage(data);

   /*
	  If user exists, get domain usage
   */

   if (uusage != -1) {
	  for (p = data; *p; p++) {
		 if (*p == '@')
			break;
	  }

	  if (*p)
		 dusage = domain_get_usage(p + 1);
   }

   /*
	  Put user in new user queue
   */

   else
	  queue_check_newuser(data);

   /*
	  Convert to network byte order
   */

   uusage = htonll(uusage);
   dusage = htonll(dusage);

   /*
	  Write response
   */

   ret = packet_write(handle, &uusage, sizeof(uusage));
   if (!ret) {
	  fprintf(stderr, "query_parse: packet_write failed\n");
	  return 1;
   }

   ret = packet_write(handle, &dusage, sizeof(dusage));
   if (!ret) {
	  fprintf(stderr, "query_parse: packet_write failed\n");
	  return 1;
   }

#ifdef QUERY_DEBUG
   printf("query: %s: user=%llu; domain=%llu\n", data, ntohll(uusage), ntohll(dusage));
#endif
   return 1;
}

