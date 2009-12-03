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
#include <unistd.h>
#include <string.h>
#include "vpopmail.h"
#include "vauthmodule.h"
#include "group.h"

extern int optind;
static void usage(const char *);
static int load_group(group_t *, char *);
static void show_group(group_t *);
static void add_member(group_t *, char *);
static void remove_member(group_t *, char *);
static void set_quota(group_t *, char *);
static void create_group(group_t *, char *);
static void set_members(group_t *, char *);

int main(int argc, char *argv[])
{
   group_t g;
   int ret = 0, c = 0;

   if (argc < 2) {
	  usage(argv[0]);
	  return 1;
   }

   /*
	  Load authentication module
   */

   ret = vauth_load_module(NULL);
   if (!ret)
	  vexiterror(stderr, "could not load authentication module");

   if (vauth_open(1))
	  vexiterror(stderr, "Initial open." );

   group_init(&g);

   /*
	  Get operation
   */	  

   c = getopt(argc, argv, "nsr:a:q:m:");
   if ((c == -1) || (optind >= argc)) {
	  usage(argv[0]);
	  return 1;
   }

   /*
	  Perform operation
   */

   switch(c) {
	  case 's':
		 load_group(&g, argv[optind]);
		 show_group(&g);
		 break;

	  case 'q':
		 load_group(&g, argv[optind]);
		 set_quota(&g, optarg);
		 break;

	  case 'm':
		 load_group(&g, argv[optind]);
		 set_members(&g, optarg);
		 break;

	  case 'n':
		 group_reset(&g);
		 create_group(&g, argv[optind]);
		 break;

	  case 'a':
		 load_group(&g, argv[optind]);
		 add_member(&g, optarg);
		 break;

	  case 'r':
		 load_group(&g, argv[optind]);
		 remove_member(&g, optarg);
		 break;

	  default:
		 usage(argv[0]);
		 return 1;
   }

   group_reset(&g);
   return 0;
}

/*
   Print usage
*/

static void usage(const char *argv0)
{
   printf("Usage: %s <operation> <group>\n", argv0);
   printf("Operations:\n");
   printf("  -n            Make address owner of a new group\n");
   printf("  -s            Display group statistics\n"); 
   printf("  -a <address>  Add existing account to group\n");
   printf("  -r <address>  Remove account from group\n");
   printf("  -m <members>  Set maximum member count for group\n");
   printf("  -q <quota>    Set default quota for group\n");
}

/*
   Load group
*/

static int load_group(group_t *g, char *owner)
{
   int ret = 0;
   char *user = NULL, *domain = NULL;

   /*
	  Parse out group to load
   */
   
   for (user = domain = owner; *domain; domain++) {
	  if (*domain == '@')
		 break;
   }

   if (!(*domain)) {
	  printf("%s is not a valid address\n", owner);
	  exit(1);
   }

   *domain++ = '\0';

   ret = group_load(user, domain, g);
   if (!ret) {
	  printf("%s@%s is not a group owner or member\n", user, domain);
	  exit(1);
   }

   *(domain - 1) = '@';

   /*
	  Don't let them load a group from a member
   */

   if (strcasecmp(g->owner, owner)) {
	  printf("%s is a member of %s's group\n", user, g->owner);
	  return 0;
   }

   *(domain - 1) = '\0';

   return 1;
}

/*
   Print group statistics
*/

static void show_group(group_t *g)
{
   int i = 0, len = 0;

   printf("Default quota: %d\n", g->quota);
   printf("Members: %d/%d\n", g->n_members, g->max_members);

   for (len = 0, i = 0; i < g->n_members; i++) {
	  if (len)
		 printf(", ");
	  else
		 printf("\t");

	  printf("%s", g->member[i]);

	  len += strlen(g->member[i]);

	  if (len >= 50) {
		 printf("\n");
		 len = 0;
	  }
   }

   if (len)
	  printf("\n");
}

/*
   Add member to group
*/

static void add_member(group_t *g, char *address)
{
   int ret = 0;
   char user[255] = { 0 }, *p = NULL;

   if (g->n_members >= g->max_members) {
	  printf("%s's group is full\n", g->owner);
	  return;
   }

   for (p = address; *p; p++) {
	  if (*p == '@')
		 break;
   }

   if (!(*p)) {
	  printf("%s: invalid address\n", address);
	  return;
   }

   memset(user, 0, sizeof(user));
   ret = (p - address);

   if (ret >= sizeof(user)) {
	  printf("%s: address too large\n", address);
	  return;
   }

   memcpy(user, address, ret);

   p++;

   ret = group_add(g, user, p);
   if (!ret) {
	  printf("group_add failed\n");
	  return;
   }

   printf("Added %s to %s's group\n", address, g->owner);
}

/*
   Remove member from group
*/

static void remove_member(group_t *g, char *address)
{
   int ret = 0;
   char user[255] = { 0 }, *p = NULL;

   for (p = address; *p; p++) {
	  if (*p == '@')
		 break;
   }

   if (!(*p)) {
	  printf("%s: invalid address\n", address);
	  return;
   }

   memset(user, 0, sizeof(user));
   ret = (p - address);

   if (ret >= sizeof(user)) {
	  printf("%s: address too large\n", address);
	  return;
   }

   memcpy(user, address, ret);

   p++;

   ret = group_remove(g, user, p);
   if (!ret) {
	  printf("group_remove failed\n");
	  return;
   }

   printf("Removed %s from %s's group\n", address, g->owner);
}

/*
   Set default quota for new group members
*/

static void set_quota(group_t *g, char *quotastr)
{
   int ret = 0;
   unsigned long q = 0;

   q = -1;

   if (!(strcasecmp(quotastr, "NOQUOTA")))
	  q = 0;
   
   else
	  q = atol(quotastr);

   g->quota = (int)q;
   
   ret = group_write(g);
   if (!ret)
	  printf("group_write failed\n");
   else {
	  if (g->quota == 0)
		 printf("Unset default quota\n");
	  else
		 printf("Set default quota to %d\n", g->quota);
   }
}

/*
   Set existing user as a group owner
*/

static void create_group(group_t *g, char *address)
{
   int ret = 0;
   char user[255] = { 0 }, *p = NULL;

   for (p = address; *p; p++) {
	  if (*p == '@')
		 break;
   }

   if (!(*p)) {
	  printf("%s: invalid address\n", address);
	  return;
   }

   memset(user, 0, sizeof(user));
   ret = (p - address);

   if (ret >= sizeof(user)) {
	  printf("%s: address too large\n", address);
	  return;
   }

   memcpy(user, address, ret);

   p++;

   ret = group_new(g, user, p);
   if (!ret) {
	  printf("group_new failed\n");
	  return;
   }

   printf("Created group for %s\n", address);
}

/*
   Set maximum member count
*/

static void set_members(group_t *g, char *cntstr)
{
   int ret = 0;

   g->max_members = atoi(cntstr);

   ret = group_write(g);
   if (!ret) {
	  printf("group_write failed\n");
	  return;
   }

   printf("Set maximum members to %d\n", g->max_members);
}
