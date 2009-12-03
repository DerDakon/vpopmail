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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef ASSERT_DEBUG
   #include <assert.h>
#endif
#include <errno.h>
#include <vauth.h>
#include <vauthmodule.h>
#include <conf.h>
#include "path.h"
#include "../storage.h"
#include "cache.h"
#include "userstore.h"
#include "domain.h"
#include "queue.h"
#include "user.h"

/*
   Linked list of all users currently allocated
*/

static user_t *userlist = NULL;
static storage_t userlist_num = 0;

/*
   Location of storage file
*/

static const char *user_storage = NULL;

static user_t *user_load(const char *);
static void user_remove(user_t *);
static void user_free(user_t *);
static int user_storage_load(void);
static inline int user_userlist_add(user_t *);

/*
   Initialize user system
*/

int user_init(config_t *config)
{
   int ret = 0;
   const char *s = NULL;

#ifdef ASSERT_DEBUG
   assert(config != NULL);
#endif

   /*
	  Initialize userlist
   */

   userlist_num = 0;
   userlist = NULL;

   /*
	  Load configurations
   */

   s = config_fetch_by_name(config, "Storage", "Filename");
   if ((s) && (*s)) {
	  if (strlen(s) >= 256) {
		 fprintf(stderr, "user_init: Storage::Filename: value too long\n");
		 return 0;
	  }

	  user_storage = strdup(s);
	  if (user_storage == NULL) {
		 fprintf(stderr, "user_init: strdup failed\n");
		 return 0;
	  }
   }

   /*
	  Try to load saved data, if any
   */

   ret = user_storage_load();
   if (!ret)
	  fprintf(stderr, "user_init: warning: user_storage_load failed\n");

   return 1;
}

/*
   Return a user handle from email address
   This function always returns a value if the
   user exists on the system
*/

user_t *user_get(const char *email)
{
   user_t *u = NULL;
   const char *p = NULL;

#ifdef ASSERT_DEBUG
   assert(email != NULL);
   assert(*(email) != '\0');

   for (p = email; *p; p++) {
	  if ((p - email) > 600)
		 assert("extremely long email address in user_get" == NULL);
   }
#endif

   /*
	  Do quick initial format test
   */

   for (p = email; *p; p++) {
	  if (*p == '@')
		 break;
   }

   if (!(*p))
	  return NULL;

   if (!(*(p + 1)))
	  return NULL;

   /*
	  Look for user in the cache
   */

   u = cache_lookup(email);
   if (u == NULL) {
	  /*
		 Load up previously unloaded user
	  */

	  u = user_load(email);
	  if (u == NULL) {
		 fprintf(stderr, "user_get: user_load failed\n");
		 return NULL;
	  }
   }

#ifdef ASSERT_DEBUG
   else {
	  assert(u->user != NULL);
	  assert(*(u->user) != '\0');
	  assert(u->domain != NULL);
	  assert(*(u->domain->domain) != '\0');
	  assert(!(strncasecmp(u->user, email, (p - email))));
	  assert(!(strncasecmp((p + 1), u->domain->domain, strlen(p + 1))));
   }
#endif

   return u;
}

/*
   Return the current approximate usage of a user
*/

storage_t user_usage(user_t *u)
{
   storage_t usage = 0;

#ifdef ASSERT_DEBUG
   assert(u != NULL);
#endif

   /*
	  Waiting for data still
   */

   if (u->userstore == NULL)
	  return 0;

   usage = userstore_usage(u->userstore);
   return usage;
}

/*
   Look up a user in the cache and return usage
   Does not call user_load to be called
*/

storage_t user_get_usage(const char *user)
{
   user_t *u = NULL;

   u = cache_lookup(user);
   if (u == NULL)
	  return -1;

   if (u->userstore == NULL)
	  return 0;

   return userstore_usage(u->userstore);
}

/*
   Look up a user and return size and counts
*/

int user_get_use(const char *user, storage_t *susage, storage_t *cusage)
{
   user_t *u = NULL;

   u = cache_lookup(user);
   if (u == NULL)
	  return -1;

   if ((susage == NULL) || (cusage == NULL))
	  return 0;

   if (u->userstore == NULL)
	  return 0;

   userstore_use(u->userstore, susage, cusage);
   return 1;
}


/*
   Allocate a user structure and fill it
   This should only be called by the controller thread
   since vpopmail is not thread-safe
*/

static user_t *user_load(const char *email)
{
   user_t *u = NULL;
   int ret = 0, len = 0;
   struct vqpasswd *pw = NULL;
   char *home = NULL;
   const char *p = NULL;
   char user[USER_MAX_USERNAME] = { 0 }, domain[DOMAIN_MAX_DOMAIN] = { 0 };
   domain_t *dom = NULL;
   userstore_t *userstore = NULL;

#ifdef ASSERT_DEBUG
   assert(email != NULL);
   assert(*(email) != '\0');
#endif

   /*
	  Find user@domain seperator
   */

   for (p = email; *p; p++) {
	  if (*p == '@')
		 break;
   }

   /*
	  Enforce format
   */

   if (!(*p))
	  return NULL;

   /*
	  vpopmail can mangle; We cannot
   */

   len = (p - email);
   if (len >= sizeof(user)) {
	  fprintf(stderr, "user_load: username too long\n");
	  return NULL;
   }

   memcpy(user, email, len);
   *(user + len) = '\0';

   len = strlen(p + 1);
   if (len >= sizeof(domain)) {
	  fprintf(stderr, "user_load: domain too long\n");
	  return NULL;
   }
   
   memcpy(domain, p + 1, len);
   *(domain + len) = '\0';

   /*
	  Look up user in vpopmail
   */

   pw = vauth_getpw(user, domain);
   if (pw == NULL) {
	  fprintf(stderr, "user_get: vauth_getpw(%s, %s) failed\n", user, domain);
	  return NULL;
   }

   /*
	  Our root directory is the Maildir of the user
   */

   len = (strlen(pw->pw_dir) + strlen("/Maildir"));
   home = malloc(len + 1);
   if (home == NULL) {
	  fprintf(stderr, "user_get: malloc failed\n");
	  return NULL;
   }

   snprintf(home, len + 1, "%s/Maildir", pw->pw_dir);
   *(home + len) = '\0';

   /*
	  Load the domain
   */

   dom = domain_load(domain);
   if (dom == NULL) {
	  fprintf(stderr, "user_get: domain_load failed\n");
	  free(home);
	  return NULL;
   }

   /*
	  Allocate structure
   */

   u = malloc(sizeof(user_t));
   if (u == NULL) {
	  fprintf(stderr, "user_load: malloc failed\n");
	  return NULL;
   }

   memset(u, 0, sizeof(user_t));

   /*
	  Copy username
   */

   len = (p - email);
   u->user = malloc(len + 1);
   if (u->user == NULL) {
	  fprintf(stderr, "user_load: malloc failed\n");
	  free(u);
	  free(home);
	  userstore_free(userstore);
	  domain_free(dom);
	  return NULL;
   }

   memset(u->user, 0, len + 1);
   memcpy(u->user, email, len);

   u->home = home;
   u->domain = dom;
   u->userstore = NULL;

   /*
	  Add to userlist
   */

   ret = user_userlist_add(u);
   if (!ret) {
	  user_free(u);
	  fprintf(stderr, "user_load: user_userlist_add failed\n");
	  return NULL;
   }

   return u;
}

/*
   Remove user structure from user list linked list
*/

static void user_remove(user_t *u)
{
#ifdef ASSERT_DEBUG
   assert(u != NULL);
   assert(userlist != NULL);
   assert(userlist_num > 0);
#endif

   if (u->next)
	  u->next->prev = u->prev;

   if (u->prev)
	  u->prev->next = u->next;

   if (u == userlist)
	  userlist = u->next;

   userlist_num--;
}

/*
   Deallocate a user structure
*/

static void user_free(user_t *u)
{
#ifdef ASSERT_DEBUG
   assert(u != NULL);
#endif

   if (u->home)
	  free(u->home);

   if (u->user)
	  free(u->user);

   if (u->userstore)
	  userstore_free(u->userstore);

   free(u);
}

/*
   Update user structure
*/

int user_poll(user_t *u)
{
   int ret = 0;
   storage_t before = 0, cbefore = 0, after = 0, cafter = 0;

#ifdef ASSERT_DEBUG
   assert(u != NULL);
   assert(u->user != NULL);
   assert(u->domain != NULL);
   assert(u->domain->domain != NULL);
#endif

   /*
	  Load the userstore if it hasn't already been loaded
   */

   if (u->userstore == NULL) {
	  u->userstore = userstore_load(u->home);
	  before = cbefore = 0;
   }

   /*
	  Otherwise poll for changes
   */

   else {
	  userstore_use(u->userstore, &before, &cbefore);
	  ret = userstore_poll(u->userstore);
   }
   
   /*
	  Update domain record
   */

   if (u->userstore) {
	  userstore_use(u->userstore, &after, &cafter);

	  ret = domain_update(u->domain, before, after, cbefore, cafter);
	  if (!ret)
		 fprintf(stderr, "user_poll: domain_update failed\n");
   }

   return 1;
}

/*
   Return pointer to userlist
*/

user_t *user_get_userlist(void)
{
   return userlist;
}

/*
   Returns if a user exists within vpopmail
   This function should only be called by the controller
   thread because vpopmail is not thread-safe
*/

int user_verify(user_t *u)
{
   int ret = 0;
   storage_t usage = 0, count = 0;
   char b[USER_MAX_USERNAME + DOMAIN_MAX_DOMAIN] = { 0 };

#ifdef ASSERT_DEBUG
   assert(u != NULL);
   assert(u->user != NULL);
   assert(u->domain != NULL);
   assert(u->domain->domain != NULL);
#endif

   if (vauth_getpw(u->user, u->domain->domain) == NULL) {
#ifdef USER_DEBUG
	  printf("user: lost %s@%s\n", u->user, u->domain->domain);
#endif

	  ret = snprintf(b, sizeof(b), "%s@%s", u->user, u->domain->domain);
	  *(b + ret) = '\0';

	  /*
		 Update domain usage
	  */

	  if (u->userstore) {
		 userstore_use(u->userstore, &usage, &count);
		 domain_update(u->domain, usage, 0, count, 0);
	  }

	  /*
		 Remove user from the cache and free all memory
		 associated with it
	  */

	  cache_remove(b);
	  user_remove(u);
	  user_free(u);

	  /*
		 Return verification failed
	  */

	  return 0;
   }

   /*
	  User is a vpopmail user
   */

   return 1;
}

/*
   Load saved user list data
*/

static int user_storage_load(void)
{
   int fd = 0, ret = 0;
   ssize_t rret = 0;
   storage_t num = 0;
   user_t *u = NULL;
   user_storage_header_t header;
   user_storage_entry_t entry;
   domain_t *d = NULL;

   /*
	  No storage
   */

   if (user_storage == NULL)
	  return 1;

   /*
	  Open database
   */

   fd = open(user_storage, O_RDONLY);
   if (fd == -1) {
	  if (errno != ENOENT) {
		 fprintf(stderr, "user_storage_load: open(%s) failed: %d\n", user_storage, errno);
		 return 0;
	  }

	  /*
		 No database file exists
	  */

	  return 1;
   }

   printf("user: loading database: %s\n", user_storage);
   
   /*
	  Read header
   */

   rret = read(fd, &header, sizeof(header));
   if (rret != sizeof(header)) {
	  fprintf(stderr, "user_storage_load: read failed: %d (errno = %d)\n", rret, errno);
	  close(fd);
	  return 0;
   }

   /*
	  Check initial values
   */

   if (strncmp((const char *)header.id, USER_STORAGE_ID, 3)) {
	  close(fd);
	  printf("user: not a vusaged database file\n");
	  return 0;
   }

   if (header.version != 0x01) {
	  close(fd);
	  printf("user: don't know how to handle version %d database files\n", header.version);
	  return 0;
   }

   /*
	  Fix values
   */

   header.num_entries = ntohll(header.num_entries);

   printf("user: loading %llu entries\n", header.num_entries);

   /*
	  Load entries
   */

   for (num = 0; num < header.num_entries; num++) {
	  /*
		 Read entry
	  */

	  rret = read(fd, &entry, sizeof(entry));
	  if (rret != sizeof(entry)) {
		 fprintf(stderr, "user_storage_load: read failed: %d\n", errno);
		 break;
	  }

	  /*
		 Fix values
	  */

	  entry.bytes = ntohll(entry.bytes);
	  entry.count = ntohll(entry.count);

	  /*
		 Load domain
	  */

	  d = domain_load((const char *)entry.domain);
	  if (d == NULL) {
		 fprintf(stderr, "user_storage_load: domain_load failed\n");
		 break;
	  }

	  /*
		 Manually load user
	  */

	  u = malloc(sizeof(user_t));
	  if (u == NULL) {
		 fprintf(stderr, "user_storage_load: malloc failed\n");
		 break;
	  }

	  memset(u, 0, sizeof(user_t));

	  /*
		 Copy entry values
	  */

	  u->home = strdup((const char *)entry.home);
	  if (u->home == NULL) {
		 fprintf(stderr, "user_storage_load: strdup failed\n");
		 user_free(u);
		 break;
	  }

	  u->user = strdup((const char *)entry.user);
	  if (u->user == NULL) {
		 fprintf(stderr, "user_storage_load: strdup failed\n");
		 user_free(u);
		 break;
	  }

	  /*
		 Set domain
	  */

	  u->domain = d;

	  /*
		 Allocate userstore
	  */

	  u->userstore = userstore_load(u->home);
	  if (u->userstore == NULL) {
		 user_free(u);
		 fprintf(stderr, "user_storage_load: userstore_load failed\n");
		 break;
	  }

	  /*
		 Manually set usage counts
	  */

	  u->userstore->usage = entry.bytes;
	  u->userstore->count = entry.count;

	  /*
		 Manually skip a poll period
	  */

	  u->userstore->time_taken = 1;

	  /*
		 Update domain
	  */

	  ret = domain_update(u->domain, 0, entry.bytes, 0, entry.count);
	  if (!ret) {
		 user_free(u);
		 fprintf(stderr, "user_load_storage: domain_update failed\n");
		 break;
	  }

	  /*
		 Add to userlist
	  */

	  ret = user_userlist_add(u);
	  if (!ret) {
		 user_free(u);
		 fprintf(stderr, "user_load_storage: user_userlist_add failed\n");
		 break;
	  }

#ifdef USER_DEBUG
	  printf("user: database: loaded %s@%s; usage=%llu; count=%llu;\n", u->user, u->domain->domain, u->userstore->usage, u->userstore->count);
#endif
   }

   /*
	  Done
   */

   close(fd);

   /*
	  Check number of read entries vs number of reported entries
   */

   if (num != header.num_entries)
	  printf("user: warning: loaded %llu/%llu entries\n", num, header.num_entries);
   else
	  printf("user: database loaded\n");

   return 1;
}

/*
   Save user list data
*/

int user_storage_save(void)
{
   int fd = 0, ret = 0;
   user_t *u = NULL;
   storage_t num = 0;
   user_storage_entry_t entry;
   user_storage_header_t header;

   /*
	  No storage configured
   */

   if (user_storage == NULL)
	  return 1;

   printf("user: saving database\n");

   /*
	  Truncate storage file
   */

   fd = open(user_storage, O_WRONLY|O_CREAT|O_TRUNC, 0600);
   if (fd == -1) {
	  fprintf(stderr, "user_storage_save: open(%s) failed: %d\n", user_storage, errno);
	  return 0;
   }

   /*
	  Fill header
   */

   memset(&header, 0, sizeof(header));

   header.version = 1;
   memcpy(header.id, USER_STORAGE_ID, 3);
   header.num_entries = htonll(userlist_num);

   /*
	  Write header
   */

   ret = write(fd, &header, sizeof(header));
   if (ret != sizeof(header)) {
	  unlink(user_storage);
	  close(fd);
	  fprintf(stderr, "user_storage_save: write failed: %d\n", errno);
	  return 0;
   }

   /*
	  Fix values
   */

   header.num_entries = ntohll(header.num_entries);

   /*
	  Write userlist
   */

   /*
	  Run through userlist
   */

   num = 0;
   for (u = userlist; u; u = u->next) {
	  /*
		 Form address
	  */

	  if (u->user == NULL) {
		 printf("user: warning: invalid entry in database\n");
		 continue;
	  }

	  if ((u->domain == NULL) || (u->domain->domain == NULL)) {
		 printf("user: warning: invalid entry in database\n");
		 continue;
	  }

	  /*
		 Fill entry structure
	  */

	  ret = strlen(u->user);
	  if (ret >= sizeof(entry.user)) {
		 printf("user: warning: long entry in database\n");
		 continue;
	  }

	  memset(entry.user, 0, sizeof(entry.user));
	  memcpy(entry.user, u->user, ret);

	  ret = strlen(u->domain->domain);
	  if (ret >= sizeof(entry.domain)) {
		 printf("user: warning: long entry in database\n");
		 continue;
	  }

	  memset(entry.domain, 0, sizeof(entry.domain));
	  memcpy(entry.domain, u->domain->domain, ret);

	  ret = strlen(u->home);
	  if (ret >= sizeof(entry.home)) {
		 printf("user: warning: long entry in database\n");
		 continue;
	  }

	  memset(entry.home, 0, sizeof(entry.home));
	  memcpy(entry.home, u->home, ret);

	  if (u->userstore) {
		 entry.bytes = htonll(u->userstore->usage);
		 entry.count = htonll(u->userstore->count);
	  }

	  else {
		 entry.bytes = 0;
		 entry.count = 0;
	  }

	  /*
		 Write entry
	  */

	  ret = write(fd, &entry, sizeof(user_storage_entry_t));
	  if (ret != sizeof(user_storage_entry_t)) {
		 unlink(user_storage);
		 close(fd);
		 fprintf(stderr, "user_storage_save: write failed: %d\n", errno);
		 return 0;
	  }

	  num++;
   }

   /*
	  Done
   */

   close(fd);

   /*
	  Sanity check
   */

   if (num != userlist_num)
	  printf("user: warning: saved %llu/%llu entries\n", num, userlist_num);
   else
	  printf("user: saved %llu user(s)\n", userlist_num);

   return 1;
}

/*
   Add user to userlist
*/

static inline int user_userlist_add(user_t *u)
{
   int ret = 0;
   char b[384] = { 0 };

#ifdef ASSERT_DEBUG
   assert(u != NULL);
   assert(u->domain != NULL);
   assert(u->domain->domain != NULL);
   assert(u->home != NULL);
   assert(u->user != NULL);
#endif

   if (userlist)
	  userlist->prev = u;

   u->next = userlist;
   userlist = u;

   userlist_num++;

   /*
	  Add to cache
   */

   ret = snprintf(b, sizeof(b), "%s@%s", u->user, u->domain->domain);
   if (ret >= sizeof(b)) {
	  fprintf(stderr, "user_userlist_add: address too long\n");
	  return 0;
   }

   ret = cache_add(b, u);
   if (!ret) {
	  fprintf(stderr, "user_userlist_add: cache_add failed\n");
	  return 0;
   }

   return 1;
}
