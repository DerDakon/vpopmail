/*
 * $Id$
 * Copyright (C) 2009 Inter7 Internet Technologies, Inc
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
#include <stdint.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "config.h"
#include "vauthmodule.h"
#include "vpopmail.h"

extern int verrori;

/*
   Functions that are required to be exported
   by authentication modules
*/

#define VAUTH_MF_NONE     0
#define VAUTH_MF_OPTIONAL 1

struct vauth_required_func {
   const char *name;
   void *func;
   int flags;
};

/*
   Catch calls to force module load for programs
   not following 5.5 API
*/

static int (*auth_open_ptr)(int) = NULL;
static void (*vvclose_ptr)(void) = NULL;

static struct vauth_required_func vauth_required_functions[] = {
   { "auth_open", &auth_open_ptr, 0 },
   { "auth_adddomain", &vauth_adddomain, 0 },
   { "auth_deldomain", &vauth_deldomain, 0},
   { "auth_adduser", &vauth_adduser, 0 },
   { "auth_crypt", &vauth_crypt, 0 },
   { "auth_deluser", &vauth_deluser, 0 },
   { "auth_setpw", &vauth_setpw, 0 },
   { "auth_getpw", &vauth_getpw, 0 },
   { "auth_setquota", &vauth_setquota, 0 },
   { "auth_getall", &vauth_getall, 0 },
   { "auth_end_getall", &vauth_end_getall, 0 },
   { "mkpasswd", &vmkpasswd, VAUTH_MF_OPTIONAL },
   { "vvclose", &vvclose_ptr, 0 },
#ifdef ENABLE_AUTH_LOGGING
   { "set_lastauth", &vset_lastauth, 0 },
   { "get_lastauth", &vget_lastauth, 0 },
#endif
   { "read_dir_control", &vread_dir_control, 0 },
   { "write_dir_control", &vwrite_dir_control, 0 },
   { "del_dir_control", &vdel_dir_control, 0 },
   { NULL, NULL }
};

static int vauth_find_module_function(const char *);

/*
   Not thread-safe, but none of vpopmail is right now
*/

static void *auth_module_handle = NULL;
static char *auth_module_name = NULL;

/*
   Load an authentication module
*/

int vauth_load_module(const char *module)
{
   int i = 0, fd = 0;
   char b[1024] = { 0 }, *p = NULL;
   void *hand = NULL, *sym = NULL;

   /*
	  Load the module
   */

   if (module == NULL) {
	  memset(b, 0, sizeof(b));
	  snprintf(b, sizeof(b), "%s/etc/vpopmail.authmodule", VPOPMAILDIR);

	  module = (const char *)b;
   }

   hand = dlopen(module, RTLD_GLOBAL|RTLD_NOW);
   if (hand == NULL) {
	  fprintf(stderr, "vauth_load_module: dlopen(%s) failed: %d\n",
			module, errno);
	  verrori = VA_NO_AUTH_MODULE;
	  return 0;
   }

   /*
	  Get module name
   */

   sym = dlsym(hand, "auth_module_name");
   if (sym == NULL) {
	  dlclose(hand);
	  fprintf(stderr, "vauth_load_module: dlsym(auth_module_name) failed: %d\n", errno);
	  verrori = VA_NO_AUTH_MODULE;
	  return 0;
   }

   auth_module_name = sym;

   /*
	  Load exported functions
   */

   for (i = 0; vauth_required_functions[i].name; i++) {
	  sym = dlsym(hand, vauth_required_functions[i].name);
	  if ((sym == NULL) && (!(vauth_required_functions[i].flags & VAUTH_MF_OPTIONAL))) {
		 dlclose(hand);
		 fprintf(stderr, "vauth_load_module: %s: dlsym(%s) failed: %d\n",
			   module, vauth_required_functions[i].name, errno);
		 verrori = VA_NO_AUTH_MODULE;
		 return 0;
	  }

	  *(intptr_t *)(vauth_required_functions[i].func) = (intptr_t)sym;
   }

   /*
	  Assign global module handle
   */

   auth_module_handle = hand;
   return 1;
}

/*
   Automatically call vauth_load_module() if vauth_open is caught
*/

int vauth_open(int x)
{
   int ret = 0;

   /*
	  If the module has already been loaded
	  call the real vauth_open
   */

   if (auth_module_handle) {
	  if (auth_open_ptr == NULL) {
		 fprintf(stderr, "vauth_open: no auth_open pointer\n");
		 return 1;
	  }

	  return auth_open_ptr(x);
   }

   /*
	  If we haven't loaded a module yet, try and then repeat
	  this call
   */

   ret = vauth_load_module(NULL);
   if (!ret) {
	  fprintf(stderr, "vauth_open: vauth_load_module failed\n");
	  return 0;
   }

   return vauth_open(x);
}

/*
   Prevents segfaults if vclose is called when vauth_load_module() fails
*/

void vclose(void)
{
   if (auth_module_handle == NULL)
	  return;

   if (vvclose_ptr == NULL)
	  return;

   /*
	  Call the real vclose() if a module is loaded
   */

   vvclose_ptr();
}

/*
   Returns pointer for a function
*/

static int vauth_find_module_function(const char *name)
{
   int i = 0;
   
   for (i = 0; vauth_required_functions[i].name; i++) {
	  if (!(strcasecmp(vauth_required_functions[i].name, name)))
		 return i;
   }

   return -1;
}

/*
   Returns currently loaded module name
*/

const char *vauth_module_name(void)
{
   return auth_module_name;
}
