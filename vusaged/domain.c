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
#include <string.h>
#include <stdlib.h>
#ifdef ASSERT_DEBUG
   #include <assert.h>
#endif
#include "storage.h"
#include "cache.h"
#include "domain.h"

/*
   Allocate a new domain structure
*/

domain_t *domain_load(const char *domain)
{
   int ret = 0;
   domain_t *d = NULL;
   char b[DOMAIN_MAX_DOMAIN] = { 0 };

#ifdef ASSERT_DEBUG
   assert(domain != NULL);
   assert(*domain != '\0');
#endif

   d = domain_get(domain);
   if (d)
	  return d;

   d = malloc(sizeof(domain_t));
   if (d == NULL) {
	  fprintf(stderr, "domain_alloc: malloc failed\n");
	  return NULL;
   }

   memset(d, 0, sizeof(domain_t));

   d->domain = strdup(domain);
   if (d->domain == NULL) {
	  free(d);
	  fprintf(stderr, "domain_alloc: strdup failed\n");
	  return NULL;
   }

   memset(b, 0, sizeof(b));
   snprintf(b, sizeof(b), "@%s", domain);

   ret = cache_add(b, d);
   if (!ret) {
	  free(d->domain);
	  free(d);
	  fprintf(stderr, "domain_alloc: cache_add failed\n");
	  return NULL;
   }

   return d;
}

/*
   Deallocate a domain
*/

void domain_free(domain_t *d)
{
#ifdef ASSERT_DEBUG
   assert(d != NULL);
#endif

   if (d->domain)
	  free(d->domain);

   free(d);
}

/*
   Look a domain up in the cache
*/

domain_t *domain_get(const char *domain)
{
   char b[DOMAIN_MAX_DOMAIN] = { 0 };

#ifdef ASSERT_DEBUG
   assert(domain != NULL);
   assert(*domain != '\0');
#endif

   memset(b, 0, sizeof(b));
   snprintf(b, sizeof(b), "@%s", domain);

   return cache_lookup(b);
}

/*
   Return domain usage
*/

storage_t domain_usage(domain_t *d)
{
#ifdef ASSERT_DEBUG
   assert(d != NULL);
#endif

   return d->usage;
}

/*
   Look up domain in the cache and return usage
*/

storage_t domain_get_usage(const char *domain)
{
   domain_t *d = NULL;

#ifdef ASSERT_DEBUG
   assert(domain != NULL);
#endif

   d = domain_get(domain);
   if (d == NULL)
	  return -1;

   return domain_usage(d);
}

/*
   Express a change in estimated storage under a domain
*/

int domain_update(domain_t *d, storage_t before, storage_t after)
{
#ifdef ASSERT_DEBUG
   assert(d != NULL);
#endif

   d->usage -= before;
   d->usage += after;

   return 1;
}
