/*
   $Id$
*/

#ifndef __VDB_H_
   #define __VDB_H_

#include <storage.h>
#include <conf.h>

/*
   Saved user database header
*/

#define VDB_HEADER_ID "vDB"

typedef struct __vdb_header_ {
   unsigned char id[3];
   unsigned char version;
   storage_t num_domains;
   storage_t num_users;
} vdb_header_t;

int vdb_init(config_t *);
int vdb_save(void);

#endif
