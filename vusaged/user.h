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

#ifndef __USER_H_
   #define __USER_H_

#include <time.h>
#include "../conf.h"
#include "storage.h"
#include "domain.h"
#include "userstore.h"

/*
   Maximum length of a username
*/

#define USER_MAX_USERNAME 384

/*
   User structure
*/

typedef struct __user_ {
   char *user,
		*home;                          // Home directory of user

   domain_t *domain;
   userstore_t *userstore;
   struct __user_ *next, *prev;
} user_t;

/*
   Saved user database header
*/

#define USER_STORAGE_ID "vDB"

typedef struct __user_storage_header_ {
   unsigned char id[3];
   unsigned char version;
   storage_t num_domains;
   storage_t num_users;
   storage_t num_entries;
} user_storage_header_t;

/*
   Saved user entry
   Minus address
*/

typedef struct __user_storage_entry_ {
   unsigned char user[128],
				 domain[256],
				 home[256];

   storage_t bytes,
			 count;
} user_storage_entry_t;

int user_init(config_t *);
user_t *user_get(const char *);
storage_t user_usage(user_t *);
storage_t user_get_usage(const char *);
int user_get_use(const char *, storage_t *, storage_t *);
int user_poll(user_t *);
// XXX
//user_t *user_get_userlist(void);
int user_verify(user_t *);
int user_storage_save(void);

#endif
