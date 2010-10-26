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
#include "vpalias.h"

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
   void *rfunc;
};

/*
   Catch calls to force module load for programs
   not following 5.5 API
*/

static int (*auth_open_ptr)(int) = NULL;
static void (*vvclose_ptr)(void) = NULL;

static struct vauth_required_func vauth_required_functions[] = {
   { "auth_open", &auth_open_ptr, 0, NULL },
   { "auth_adddomain", &vauth_adddomain, 0, NULL },
   { "auth_deldomain", &vauth_deldomain, 0, NULL},
   { "auth_adduser", &vauth_adduser, 0, NULL },
   { "auth_crypt", &vauth_crypt, 0, NULL },
   { "auth_deluser", &vauth_deluser, 0, NULL },
   { "auth_setpw", &vauth_setpw, 0, NULL },
   { "auth_getpw", &vauth_getpw, 0, NULL },
   { "auth_setquota", &vauth_setquota, 0, NULL },
   { "auth_getall", &vauth_getall, 0, NULL },
   { "auth_end_getall", &vauth_end_getall, 0, NULL },
   { "mkpasswd", &vmkpasswd, VAUTH_MF_OPTIONAL, NULL },
   { "vvclose", &vvclose_ptr, 0, NULL },
   { "read_dir_control", &vread_dir_control, 0, NULL },
   { "write_dir_control", &vwrite_dir_control, 0, NULL },
   { "del_dir_control", &vdel_dir_control, 0, NULL },
   { "alias_select", &valias_select, VAUTH_MF_OPTIONAL, &vpalias_select },
   { "alias_select_next", &valias_select_next, VAUTH_MF_OPTIONAL, &vpalias_select_next },
   { "alias_select_all", &valias_select_all, VAUTH_MF_OPTIONAL, &vpalias_select_all },
   { "alias_select_all_next", &valias_select_all_next, VAUTH_MF_OPTIONAL, &vpalias_select_all_next },
   { "alias_select_names", &valias_select_names, VAUTH_MF_OPTIONAL, &vpalias_select_names },
   { "alias_select_names_next", &valias_select_names_next, VAUTH_MF_OPTIONAL, &vpalias_select_names_next },
   { "alias_select_names_end", &valias_select_names_end, VAUTH_MF_OPTIONAL, &vpalias_select_names_end },
   { "alias_insert", &valias_insert, VAUTH_MF_OPTIONAL, &vpalias_insert },
   { "alias_remove", &valias_remove, VAUTH_MF_OPTIONAL, &vpalias_remove },
   { "alias_delete", &valias_delete, VAUTH_MF_OPTIONAL, &vpalias_delete },
   { "alias_delete_domain", &valias_delete_domain, VAUTH_MF_OPTIONAL, &vpalias_delete_domain },
   { "set_lastauth", &vset_lastauth, VAUTH_MF_OPTIONAL, NULL },
   { "get_lastauth", &vget_lastauth, VAUTH_MF_OPTIONAL, NULL },
   { "get_lastauthip", &vget_lastauthip, VAUTH_MF_OPTIONAL, NULL },
   { "get_ip_map", &vget_ip_map, VAUTH_MF_OPTIONAL, NULL },
   { "add_ip_map", &vadd_ip_map, VAUTH_MF_OPTIONAL, NULL },
   { "del_ip_map", &vdel_ip_map, VAUTH_MF_OPTIONAL, NULL },
   { "show_ip_map", &vshow_ip_map, VAUTH_MF_OPTIONAL, NULL },
   { NULL, NULL }
};

#if 0
static int vauth_find_module_function(const char *);
#endif

/*
   Not thread-safe, but none of vpopmail is right now
*/

static void *auth_module_handle = NULL;
static char *auth_module_name = NULL;
static char **auth_module_features = NULL;

/*
   Load an authentication module
*/

int vauth_load_module(const char *module)
{
   int i = 0;
   char b[1024] = { 0 };
   void *hand = NULL, *sym = NULL;

   /*
	  Load the module
   */

   if (module == NULL) {
	  memset(b, 0, sizeof(b));
	  snprintf(b, sizeof(b), "%s/vpopmail.authmodule", VPOPMAIL_DIR_ETC);

	  module = (const char *)b;
   }

   hand = dlopen(module, RTLD_GLOBAL|RTLD_NOW);
   if (hand == NULL) {
	  fprintf(stderr, "vauth_load_module: dlopen(%s) failed: %s\n",
			module, dlerror());
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
	  Get module features
   */

   auth_module_features = NULL;

   sym = dlsym(hand, "auth_module_features");
   if (sym)
	  auth_module_features = sym;

   /*
	  Load exported functions
   */

   for (i = 0; vauth_required_functions[i].name; i++) {
	  sym = dlsym(hand, vauth_required_functions[i].name);
	  if (sym == NULL) {
		 if (!(vauth_required_functions[i].flags & VAUTH_MF_OPTIONAL)) {
			dlclose(hand);
			fprintf(stderr, "vauth_load_module: %s: dlsym(%s) failed: %d\n",
				  module, vauth_required_functions[i].name, errno);
			verrori = VA_NO_AUTH_MODULE;
			return 0;
		 }

		 if (vauth_required_functions[i].rfunc) {
			sym = vauth_required_functions[i].rfunc;
#ifdef VAUTH_MODULE_DEBUG
			printf("%s available by replacement\n", vauth_required_functions[i].name);
#endif
		 }

#ifdef VAUTH_MODULE_DEBUG
		 else
			printf("%s not available by module\n", vauth_required_functions[i].name);
#endif
	  }

#ifdef VAUTH_MODULE_DEBUG
	  else
		 printf("%s loaded by module\n", vauth_required_functions[i].name);
#endif
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
	  return 1;
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

#if 0
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
#endif

/*
   Returns currently loaded module name
*/

const char *vauth_module_name(void)
{
   return auth_module_name;
}

/*
   Returns if current module supports a feature
*/

int vauth_module_feature(const char *name)
{
   int i = 0;

   if (auth_module_features == NULL)
	  return 0;

   for (i = 0; auth_module_features[i] != NULL; i++) {
	  if (!(strcasecmp(name, auth_module_features[i])))
		 return 1;
   }

   return 0;
}
