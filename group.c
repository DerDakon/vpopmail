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
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "vauth.h"
#include "group.h"

/*
   Warning message written to every data file
*/

static const char group_warning[] = "; This file is automatically maintained - Do not edit";

static int group_add_member(group_t *, char *, char *);
static int group_remove_member(group_t *, char *, char *);
static int group_write_member(group_t *, const char *);

/*
   Initialize group structure
*/

int group_init(group_t *g)
{
   if (g == NULL)
	  return 0;

   memset(g, 0, sizeof(group_t));
   return 1;
}

/*
   Deallocate group structure contents
*/

void group_reset(group_t *g)
{
   int i = 0;
   
   if (g->owner)
	  free(g->owner);

   if (g->member) {
	  for (i = 0; g->member[i]; i++)
		 free(g->member[i]);

	  free(g->member);
   }

   group_init(g);
}

/*
   Load a group via owner or member
*/

int group_load(char *user, char *domain, group_t *g)
{
   struct stat st;
   int ret = 0, i = 0;
   FILE *stream = NULL;
   struct vqpasswd *ppw = NULL;
   char b[255] = { 0 }, *p = NULL, *t = NULL, *h = NULL;

   group_reset(g);
   
   /*
	  Get vpopmail entry
   */

   ppw = vauth_getpw(user, domain);
   if (ppw == NULL)
	  return 0;

   /*
	  Determine if user is owner
   */

   memset(b, 0, sizeof(b));
   i = snprintf(b, sizeof(b), "%s/group_owner", ppw->pw_dir);

   memset(&st, 0, sizeof(st));
   ret = stat(b, &st);
   if (ret == -1) {

	  /*
		 Determine if user is a member
	  */

	  memset(b, 0, sizeof(b));
	  snprintf(b, sizeof(b), "%s/group_member", ppw->pw_dir);

	  memset(&st, 0, sizeof(st));
	  ret = stat(b, &st);
	  if (ret == -1)
		 return 0;

	  /*
		 Load owner of group
	  */

	  stream = fopen(b, "r");
	  if (stream == NULL) 
		 return 0;

	  /*
		 Skip warning message
	  */
	  
	  fgets(b, sizeof(b), stream);

	  /*
		 Load owner
	  */

	  fgets(b, sizeof(b), stream);
	  fclose(stream);

	  /*
		 Parse out user and domain
	  */

	  for (p = b; *p; p++) {
		 if (*p == '@')
			break;
	  }

	  /*
		 No '@' sign
	  */

	  if (!(*p))
		 return 0;

	  *p++ = '\0';
	  t = p;

	  for (; *p; p++) {
		 if ((*p == '\r') || (*p == '\n'))
			break;
	  }

	  /*
		 Didn't get all of line
	  */

	  if ((*p != '\n') && (*p != '\r'))
		 return 0;

	  *p = '\0';

	  /*
		 Call self to load group owner
	  */

	  return group_load(b, t, g);
   }

   /*
	  Save datafile location
   */

   if (i >= sizeof(g->datafile))
	  i = (sizeof(g->datafile) - 1);

   memcpy(g->datafile, b, i);

   /*
	  Load group data file
   */

   stream = fopen(b, "r");
   if (stream == NULL)
	  return 0;

   /*
	  Skip warning
   */

   fgets(b, sizeof(b), stream);

   /*
	  Load settings

	  <num mailboxes> <max mailboxes> <quota>
   */

   fgets(b, sizeof(b), stream);

   /*
	  Terminate line
   */

   for (p = b; *p; p++) {
	  if ((*p == '\r') || (*p == '\n'))
		 break;
   }

   if ((*p != '\n') && (*p != '\r')) {
	  fclose(stream);
	  return 0;
   }
   
   /*
	  Number of mailboxes
   */

   for (h = t = b; *h; h++) {
	  if (*h == ' ')
		 break;
   }

   if (!(*h)) {
	  fclose(stream);
	  return 0;
   }

   *h++ = '\0';

   g->n_members = atoi(t);

   /*
	  Maximum mailboxes
   */

   for (t = h; *h; h++) {
	  if (*h == ' ')
		 break;
   }
   
   if (!(*h)) {
	  fclose(stream);
	  return 0;
   }

   *h++ = '\0';

   g->max_members = atoi(t);

   /*
	  Default quota
   */
   
   t = h;
   g->quota = atoi(t);

   /*
	  Read members
   */

   g->member = malloc(sizeof(char *) * (g->n_members + 1));
   if (g->member == NULL) {
	  fclose(stream);
	  return 0;
   }

   for (i = 0; i < g->n_members; i++) {
	  g->member[i] = NULL;

	  memset(b, 0, sizeof(b));
	  fgets(b, sizeof(b), stream);

	  if (feof(stream))
		 break;

	  for (p = b; *p; p++) {
		 if ((*p == '\r') || (*p == '\n'))
			break;
	  }

	  *p = '\0';

	  ret = strlen(b);

	  g->member[i] = malloc(ret + 1);
	  if (g->member[i] == NULL) {
		 fclose(stream);
		 return 0;
	  }

	  memset(g->member[i], 0, ret + 1);
	  memcpy(g->member[i], b, ret);
   }

   g->member[i] = NULL;

   /*
	  Count doesn't match
   */

   if (g->n_members != i)
	  g->n_members = i;

   if (!(feof(stream))) {
	  while(1) {
		 memset(b, 0, sizeof(b));
		 fgets(b, sizeof(b), stream);
		 if (feof(stream))
			break;

		 for (h = b; *h; h++) {
			if (*h == '@')
			   break;
		 }

		 if (!(*h)) {
			fclose(stream);
			return 0;
		 }

		 *h++ = '\0';

		 for (p = h; *p; p++) {
			if ((*p == '\n') || (*p == '\r'))
			   break;
		 }

		 *p = '\0';

		 ret = group_add_member(g, b, h);
		 if (!ret) {
			fclose(stream);
			return 0;
		 }
	  }
   }

   fclose(stream);

   /*
	  Set owner
   */

   g->owner = malloc(strlen(user) + strlen(domain) + 2);
   if (g->owner == NULL)
	  return 0;

   memset(g->owner, 0, strlen(user) + strlen(domain) + 2);
   memcpy(g->owner, user, strlen(user));
   *(g->owner + strlen(user)) = '@';
   memcpy(g->owner + strlen(user) + 1, domain, strlen(domain));

   return 1;
}

/*
   Add new member to group
*/

int group_add(group_t *g, char *user, char *domain)
{
   group_t og;
   int ret = 0;

   if ((g == NULL) || (user == NULL) || (domain == NULL) ||
		 (!(*user)) || (!(*domain)))
	  return 0;

   if (g->n_members >= g->max_members)
	  return 0;

   /*
	  Make sure new user isn't a part of a group already
   */

   ret = group_init(&og);
   if (!ret)
	  return 0;
   
   ret = group_load(user, domain, &og);
   if (ret) {
	  fprintf(stderr, "group_add: %s@%s is already in a group\n", user, domain);
	  group_reset(&og);
	  return 0;
   }

   ret = group_add_member(g, user, domain);
   if (!ret) {
	  fprintf(stderr, "group_add: group_add_member failed\n");
	  return 0;
   }

   ret = group_write(g);
   if (!ret)
	  fprintf(stderr, "group_add: group_write failed\n");

   return 1;
}

/*
   Remove member from group
*/

int group_remove(group_t *g, char *user, char *domain)
{
   int ret = 0;
   group_t og;

   if ((g == NULL) || (user == NULL) || (domain == NULL) ||
		 (!(*user)) || (!(*domain)))
	  return 0;
  
   ret = group_init(&og);
   if (!ret)
	  return 0;

   ret = group_load(user, domain, &og);
   if (!ret) {
	  fprintf(stderr, "group_remove: %s@%s is not in a group\n", user, domain);
	  return 0;
   }

   else {
	  if (strcasecmp(g->owner, og.owner)) {
		 fprintf(stderr, "group_remove: %s@%s is a part of %s's group\n", user, domain, og.owner);
		 return 0;
	  }
   }

   ret = group_remove_member(g, user, domain);
   if (!ret) {
	  fprintf(stderr, "group_remove: group_remove_member failed\n");
	  return 0;
   }

   ret = group_write(g);
   if (!ret)
	  fprintf(stderr, "group_remove: group_write failed\n");
   
   return 1;
}

/*
   Write data file
*/

int group_write(group_t *g)
{
   int i = 0, ret = 0;
   FILE *stream = NULL;

   if (g == NULL)
	  return 0;

   if ((*g->datafile != '/') || (!(*g->datafile)))
	  return 0;

   stream = fopen(g->datafile, "w");
   if (stream == NULL) {
	  fprintf(stderr, "group_write: failed to open data file\n");
	  return 0;
   }

   /*
	  Write data file
   */

   fprintf(stream, "%s\n%d %d %d\n", group_warning, g->n_members, g->max_members, g->quota);

   /*
	  Write member list
   */

   for (i = 0; i < g->n_members; i++) {
	  ret = group_write_member(g, g->member[i]);
	  if (!ret) {
		 fprintf(stderr, "group_write: group_write_member failed\n");
		 fclose(stream);
		 return 0;
	  }
	  
	  fprintf(stream, "%s\n", g->member[i]);
   }

   fclose(stream);
   return 1;
}

/*
   Set existing user as owner of a new group
*/

int group_new(group_t *g, char *user, char *domain)
{
   int ret = 0;
   char b[255] = { 0 };
   FILE *stream = NULL;
   struct vqpasswd *pw = NULL;

   /*
	  Get vpopmail entry
   */

   pw = vauth_getpw(user, domain);
   if (pw == NULL) {
	  fprintf(stderr, "group_new: no such user %s@%s\n", user, domain);
	  return 0;
   }

   /*
	  See if user is in a group already
   */

   ret = group_load(user, domain, g);
   if (ret) {
	  fprintf(stderr, "group_new: %s@%s is already in a group\n", user, domain);
	  return 0;
   }

   /*
	  Start group_owner data file
   */

   memset(b, 0, sizeof(b)); 
   ret = snprintf(b, sizeof(b), "%s/group_owner", pw->pw_dir);
   if (ret == sizeof(b)) {
	  fprintf(stderr, "group_new: path too long\n");
	  return 0;
   }

   stream = fopen(b, "w");
   if (stream == NULL) {
	  fprintf(stderr, "group_new: failed to open data file\n");
	  return 0;
   }

   fprintf(stream, "%s\n0 0 0\n", group_warning);
   fclose(stream);

   ret = group_load(user, domain, g);
   if (!ret) {
	  fprintf(stderr, "group_new: group_load failed\n");
	  return 0;
   }

   return 1;
}

/*
   Add a member to an existing member list
*/

static int group_add_member(group_t *g, char *user,  char *domain)
{
   void *ptr = NULL;
   char *addr = NULL;
   int ulen = 0, dlen = 0, alen = 0, sz = 0;

   if ((g == NULL) || (user == NULL) || (domain == NULL) ||
		 (!(*user)) || (!(*domain)))
	  return 0;

   /*
	  Determine current size
   */
   
   sz = (sizeof(char *) * (g->n_members + 1));

   /*
	  Calculate new size
   */

   sz += sizeof(char *);
   
   /*
	  Reallocate
   */

   ptr = realloc(g->member, sz);
   if (ptr == NULL)
	  return 0;

   if (g->member != ptr)
	  g->member = ptr;

   /*
	  Allocate space for new member
   */

   ulen = strlen(user);
   dlen = strlen(domain);
   alen = (ulen + dlen + 1);

   addr = malloc(alen + 1);
   if (addr == NULL)
	  return 0;

   memset(addr, 0, alen + 1);
   memcpy(addr, user, ulen);
   *(addr + ulen) = '@';
   memcpy(addr + ulen + 1, domain, dlen);

   /*
	  Update member list and count
   */

   g->member[g->n_members++] = addr;
   g->member[g->n_members] = NULL;

   return 1;
}

/*
   Remove member from group
*/

static int group_remove_member(group_t *g, char *user, char *domain)
{
   void *ptr = NULL;
   struct vqpasswd *pw = NULL;
   char *addr = NULL, b[255] = { 0 };
   int ulen = 0, dlen = 0, i = 0, ret = 0, alen = 0;

   if ((g == NULL) || (user == NULL) || (domain == NULL) ||
		 (!(*user)) || (!(*domain)))
	  return 0;

   /*
	  Look up vpopmail entry
   */

   pw = vauth_getpw(user, domain);

   /*
	  If entry exists, remove their member data file
   */

   if (pw) {
	  memset(b, 0, sizeof(b));

	  i = snprintf(b, sizeof(b), "%s/group_member", pw->pw_dir);
	  if (i < sizeof(b)) {
		 ret = unlink(b);
		 if (ret == -1)
			fprintf(stderr, "group_remove_member: warning: failed to remove member data file\n");
	  }
   }

   else
	  fprintf(stderr, "group_remove_member: warning: vpopmail entry doesn't exist\n");

   /*
	  Construct full address
   */

   ulen = strlen(user);
   dlen = strlen(domain);
   alen = (ulen + dlen + 1);

   addr = malloc(alen + 1);
   if (addr == NULL) {
	  fprintf(stderr, "group_remove_member: malloc failed\n");
	  return 0;
   }

   memset(addr, 0, alen + 1);
   memcpy(addr, user, ulen);
   *(addr + ulen) = '@';
   memcpy(addr + ulen + 1, domain, dlen);

   /*
	  Find member entry
   */

   for (i = 0; i < g->n_members; i++) {
	  if (!(strcasecmp(g->member[i], addr)))
		 break;
   }

   if (i == g->n_members) {
	  fprintf(stderr, "group_remove_member: %s is not a member of %s's group\n",
			addr, g->owner);
	  free(addr);
	  return 0;
   }

   /*
	  Shift array contents down
   */

   free(g->member[i]);

   for (; i < (g->n_members - 1); i++)
	  g->member[i] = g->member[i + 1];

   g->member[i] = NULL;

   /*
	  Change array size
   */

   g->n_members--;

   ptr = realloc(g->member, (g->n_members + 1) * sizeof(char *));
   if (ptr == NULL) {
	  fprintf(stderr, "group_remove_member: realloc failed\n");
	  return 0;
   }

   if (g->member != ptr)
	  g->member = ptr;

   return 1;
}

/*
   Write member data file
*/

static int group_write_member(group_t *g, const char *member)
{
   int len = 0;
   FILE *stream = NULL;
   char b[255] = { 0 };
   struct vqpasswd *pw = NULL;
   const char *user = NULL, *domain = NULL;
   
   if ((g == NULL) || (member == NULL) || (!(*member)))
	  return 0;

   for (user = domain = member; *domain; domain++) {
	  if (*domain == '@')
		 break;
   }

   if (!(*domain)) {
	  fprintf(stderr, "group_write_member: syntax error in address\n");
	  return 0;
   }

   memset(b, 0, sizeof(b));

   len = (domain - member);
   if (len >= sizeof(b)) {
	  fprintf(stderr, "group_write_member: syntax error in address\n");
	  return 0;
   }

   memcpy(b, member, len);
   
   domain++;

   pw = vauth_getpw(b, (char *)domain);
   if (pw == NULL) {
	  fprintf(stderr, "group_write_member: user %s@%s doesn't exist\n", b, domain);
	  return 0;
   }

   memset(b, 0, sizeof(b));
   snprintf(b, sizeof(b), "%s/group_member", pw->pw_dir);

   stream = fopen(b, "w");
   if (stream == NULL) {
	  fprintf(stderr, "group_write_member: unable to open member data file\n");
	  return 0;
   }

   fprintf(stream, "%s\n%s\n", group_warning, g->owner);
   fclose(stream);
   
   return 1;
}
