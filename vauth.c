/*
   $Id$
   Copyright (C) 2009 Inter7 Internet Technologies, Inc
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

static struct vauth_required_func vauth_required_functions[] = {
   { "auth_open", &vauth_open, 0 },
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
   { "vvclose", &vclose, 0 },
#ifdef ENABLE_AUTH_LOGGING
   { "set_lastauth", &vset_lastauth, 0 },
   { "get_lastauth", &vget_lastauth, 0 },
#endif
   { "read_dir_control", &vread_dir_control, 0 },
   { "write_dir_control", &vwrite_dir_control, 0 },
   { "del_dir_control", &vdel_dir_control, 0 },
   { NULL, NULL }
};

static void *vauth_find_module_function(const char *);

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
   So vclose() won't fail if called after a vauth_load_module failure
*/

void vauth_dummy_vclose(void)
{
}

/*
   Returns pointer for a function
*/

static void *vauth_find_module_function(const char *name)
{
   int i = 0;
   
   for (i = 0; vauth_required_functions[i].name; i++) {
	  if (!(strcasecmp(vauth_required_functions[i].name, name)))
		 return vauth_required_functions[i].func;
   }

   return NULL;
}

/*
   Returns currently loaded module name
*/

const char *vauth_module_name(void)
{
   return auth_module_name;
}
