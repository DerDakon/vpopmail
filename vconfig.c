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
#include "config.h"

/*
   Setting types
*/

#define ST_NONE    0
#define ST_STRING  1	/* Pointer to a string						*/
#define ST_INTEGER 2	/* A 32 bit value -- Even on 64 bit systems */

/*
   Setting structure
*/

struct __setting_ {
   unsigned char c,
				 type,
				 *desc;

   void *value;
};

struct __setting_ settings[] = {
   { 'b', ST_STRING,  "Binary directory",        VPOPMAIL_DIR_BIN },
   { 'c', ST_STRING,  "Configuration directory", VPOPMAIL_DIR_ETC },
   { 'i', ST_STRING,  "Includes directory",      VPOPMAIL_DIR_INCLUDE },
   { 'l', ST_STRING,  "Library directory",       VPOPMAIL_DIR_LIB },
   { 'm', ST_STRING,  "Module directory",        VPOPMAIL_DIR_LIB },
   { 'u', ST_INTEGER, "vpopmail UID (integer)",  (void *)VPOPMAILUID },
   { 'g', ST_INTEGER, "vpopmail GID (integer)",  (void *)VPOPMAILGID },
   { 'U', ST_STRING,  "vpopmail UID (string)",   VPOPUSER },
   { 'G', ST_STRING,  "vpopmail GID (string)",   VPOPGROUP },
   { 'q', ST_STRING,  "qmail directory",         QMAILDIR },
   { 'v', ST_STRING,  "vpopmail version",		 PACKAGE_VERSION },
   {   0, ST_NONE,    NULL,                      NULL }
};

static void usage(const char *);

int main(int argc, char *argv[])
{
   const char *p = NULL;
   int i = 0, ac = 0, newline = 0;

   if (argc < 2) {
	  usage(argv[0]);
	  return 1;
   }

   newline = 1;

   for (ac = 1; ac < argc; ac++) {
	  for (p = argv[ac]; *p; p++) {
		 if ((*p == ' ') || (*p == '\t') || (*p == '-') || (*p == '\r') || (*p == '\n'))
			continue;

		 if (*p == 'X') {
			newline = 0;
			continue;
		 }

		 for (i = 0; settings[i].c; i++) {
			if (*p == settings[i].c)
			   break;
		 }

		 if (!(settings[i].c)) {
			fprintf(stderr, "vconfig: warning: unknown option '%c'\n", *p);
			continue;
		 }

		 switch(settings[i].type) {
			case ST_STRING:
			   printf("%s ", (char *)settings[i].value);
			   break;

			case ST_INTEGER:
			   printf("%lu ", (unsigned long)(settings[i].value));
			   break;
			
			default:
			   fprintf(stderr, "vconfig: unknown type '%d'\n", settings[i].type);
			   break;
		 }
	  }
   }

   if (newline)
	  putchar('\n');

   return 1;
}

static void usage(const char *argv0)
{
   int i = 0;

   printf("Usage: %s <options>\n" \
	      "Options:\n", argv0);

   printf("          X Flags not to print a newline after output\n");

   for (i = 0; settings[i].c; i++)
	  printf("          %c %s\n",
			settings[i].c, settings[i].desc);
}
