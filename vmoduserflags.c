/*
 * $Id$
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
#include "vauth.h"
#include "vauthmodule.h"
#include "vpopmail.h"

/*
   Flags
*/

struct userflag {
   const char *name;
   int bits,
	   reversed;
};

static const struct userflag userflags[] = {
   { "chpass",   NO_PASSWD_CHNG,  1 },
   { "pop",      NO_POP,          1 },
   { "webmail",  NO_WEBMAIL,      1 },
   { "imap",     NO_IMAP,         1 },
   { "bounce",   BOUNCE_MAIL,     0 },
   { "relay",    NO_RELAY,        1 },
   { "dialup",   NO_DIALUP,       1 },
   { "user0",    V_USER0,         0 },
   { "user1",    V_USER1,         0 },
   { "user2",    V_USER2,         0 },
   { "user3",    V_USER3,         0 },
   { "smtp",     NO_SMTP,         1 },
   { "domadmin", QA_ADMIN,        0 },
   { "domquota", V_OVERRIDE,      1 },
   { "spam",     NO_SPAMASSASSIN, 1 },
   { "sysadmin", SA_ADMIN,        0 },
   { "expert",   SA_EXPERT,       0 },
   { "maildrop", NO_MAILDROP,     1 },
   { NULL,       0x0,             0 }
};

static void usage(const char *);
static int parse_flags(int, int, char *[]);
static void print_flags(int, int);

int main(int argc, char *argv[])
{
   int ret = 0, bits = 0;
   struct vqpasswd *pw = NULL;
   char user[128] = { 0 }, domain[256] = { 0 };

   if (argc < 2) {
	  usage(argv[0]);
	  return 1;
   }

   /*
	  Load authentication module
   */

   ret = vauth_load_module(NULL);
   if (!ret) {
	  printf("vauth_load_module failed\n");
	  return 1;
   }

   if (vauth_open(1)) {
	  printf("vauth_open failed\n");
	  return 1;
   }

   /*
	  Parse email address
   */

   ret = parse_email_safe(argv[1], user, sizeof(user), domain, sizeof(domain));
   if ((!ret) || (!(*user)) || (!(*domain))) {
	  printf("%s: Not a valid email address\n", argv[1]);
	  return 1;
   }

   /*
	  Get user information
   */

   pw = vauth_getpw(user, domain);
   if (pw == NULL) {
	  printf("%s: No such user\n", argv[1]);
	  return 1;
   }

   /*
	  Change flags
   */

   if (argc > 2) {
	  bits = parse_flags(pw->pw_gid, argc, argv);
	  if (bits == -1) {
		 printf("Couldn't parse flags\n");
		 return 1;
	  }

	  /*
		 Display changes
	  */

	  printf("Changing:");
	  print_flags(bits, pw->pw_gid);

	  /*
		 Save changes
	  */

	  pw->pw_gid = bits;

	  ret = vauth_setpw(pw, domain);
	  if (ret != 0) {
		 printf("Failed to modify user\n");
		 return 1;
	  }
   }

   /*
	  Display all flags
   */

   printf("%s:\n", argv[1]);
   print_flags(pw->pw_gid, -1);
   return 0;
}

/*
   Print usage
*/

static void usage(const char *argv0)
{
   int i = 0;

   printf("Usage: %s <email> [<+|-><option>]\n",
		 argv0);

   printf("Options:\n         ");

   for (i = 0; userflags[i].name != NULL; i++) {
	  if ((i) && ((i % 5) == 0))
		 printf("\n         ");

	  printf("%s ", userflags[i].name);
   }

   printf("\n");
}

/*
   Parses flags and returns an updated bitfield
*/

static int parse_flags(int bitfield, int argc, char *argv[])
{
   char *h = NULL, *t = NULL;
   int i = 0, mode = 0, j = 0;

   /*
	  Run through array of passed flags
   */

   for (i = 2; i < argc; i++) {
	  h = t = argv[i];

	  /*
		 Determine mode
	  */

	  if (!(*h))
		 continue;

	  if (*h == '+')
		 mode = 1;
	  else if (*h == '-')
		 mode = 0;
	  else {
		 printf("Syntax error: expected '+' or '-', got '%c' at: %s\n", *h, argv[i]);
		 mode = -1;
	  }

	  /*
		 Get flag name
	  */

	  for (t = (++h);;h++) {
		 if ((*h == ' ') || (*h == '\t') || (*h == '+') || (*h == '-') || (!(*h))) {
			if (*h)
			   *h = '\0';
			else
			   h = NULL;

			if ((*t) && (mode != -1)) {
			   /*
				  Find flag by name
			   */

			   for (j = 0; userflags[j].name != NULL; j++) {
				  if (!(strcasecmp(userflags[j].name, t))) {
					 /*
						Set flag
					 */

					 if (mode == 1) {
						if (userflags[j].reversed)
						   bitfield &= ~userflags[j].bits;
						else
						   bitfield |= userflags[j].bits;
					 }

					 /*
						Unset flag
					 */

					 else {
						if (userflags[j].reversed)
						   bitfield |= userflags[j].bits;
						else
						   bitfield &= ~userflags[j].bits;
					 }

					 break;
				  }
			   }

			   if (userflags[j].name == NULL)
				  printf("Unknown flag: %s\n", t);
			}

			if (h == NULL)
			   break;

			/*
			   Move past any whitespace
			*/

			while((*h == ' ') || (*h == '\t'))
			   h++;

			break;
		 }
	  }
   }

   return bitfield;
}

/*
   Prints flags from a bitfield optionally only printing
   if there's a change between bitfield and cmpbits
*/

static void print_flags(int bitfield, int cmpbits)
{
   int i = 0, n = 0;

   printf("  ");

   for (i = 0; userflags[i].name != NULL; i++) {
	  if ((cmpbits == -1) || ((bitfield & userflags[i].bits) != (cmpbits & userflags[i].bits))) {
		 if ((i) && (n % 5) == 0)
			printf("\n  ");

		 if (bitfield & userflags[i].bits)
			printf("%c", userflags[i].reversed ? '-' : '+');
		 else
			printf("%c", userflags[i].reversed ? '+' : '-');

		 printf("%s ", userflags[i].name);
		 n++;
	  }
   }

   if (n == 0)
	  printf("(none)");

   printf("\n");
}
