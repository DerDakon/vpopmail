/*
   $Id$
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#ifdef ASSERT_DEBUG
   #include <assert.h>
#endif
#include <storage.h>
#include <conf.h>
#include <vpopmail.h>
#include "path.h"
#include "user.h"
#include "domain.h"
#include "userstore.h"
#include "directory.h"
#include "list.h"
#include "vdb.h"

extern user_t *userlist;
extern domain_t *domainlist;
extern storage_t userlist_num, domainlist_num;

static int vdb_fd = -1;
static char *vdb_database = NULL;

static inline int vdb_write(void *, size_t);
static inline int vdb_read(void *, size_t);
static inline int vdb_close(void);
static inline int vdb_remove(void);

/*
   Read vusage database configuration
*/

int vdb_init(config_t *config)
{
   char *str = NULL;

   vdb_database = NULL;

   if (config == NULL)
	  return 0;

   str = config_fetch_by_name(config, "Storage", "Filename");
   if (str == NULL) {
	  fprintf(stderr, "vdb_init: not saving database\n");
	  return 1;
   }

   if (!(*str)) {
	  fprintf(stderr, "vdb_init: syntax error: Storage::Filename\n");
	  return 0;
   }

   vdb_database = strdup(str);
   if (vdb_database == NULL) {
	  fprintf(stderr, "vdb_init: strdup failed\n");
	  return 0;
   }

   return 1;
}

/*
   Save vusage database
*/

int vdb_save(void)
{
   int ret = 0, len = 0, l_int = 0, i = 0;
   vdb_header_t header;
   domain_t *d = NULL;
   user_t *u = NULL;
   storage_t num = 0, l_storage = 0;
   struct stat l_stat;
   time_t l_time = 0;
   char l_domain[DOMAIN_MAX_DOMAIN] = { 0 }, l_user[USER_MAX_USERNAME] = { 0 },
		l_path[PATH_MAX] = { 0 }, l_gecos[MAX_PW_GECOS] = { 0 },
		l_pass[MAX_PW_PASS] = { 0 };

   if (vdb_database == NULL)
	  return 1;

   /*
	  Truncate storage file
   */

   vdb_fd = open(vdb_database, O_WRONLY|O_CREAT|O_TRUNC, 0600);
   if (vdb_fd == -1) {
	  fprintf(stderr, "vdb_save: open(%s) failed: %d\n", vdb_database, errno);
	  return 0;
   }

   /*
	  Fill header
   */

   memset(&header, 0, sizeof(header));

   header.version = 0x03;
   memcpy(header.id, VDB_HEADER_ID, 3);
   header.num_domains = domainlist_num;
   header.num_users = userlist_num;

   ret = vdb_write(&header, sizeof(header));
   if (!ret)
	  return 0;

   /*
	  Fix values
   */

   header.num_domains = domainlist_num;
   header.num_users = userlist_num;

   /*
	  Write database
   */

   /*
	  Write domains
   */

   num = 0;

   for (d = domainlist; d; d = d->next) {
#ifdef ASSERT_DEBUG
	  assert(d->domain != NULL);
	  assert(*(d->domain) != '\0');
#endif

	  len = strlen(d->domain);
	  if (len >= sizeof(l_domain)) {
		 fprintf(stderr, "vdb_save: domain name too long: %s\n", d->domain);
		 vdb_remove();
		 return 0;
	  }

	  memset(l_domain, 0, sizeof(l_domain));
	  memcpy(l_domain, d->domain, len);

	  ret = vdb_write(l_domain, sizeof(l_domain));
	  if (!ret)
		 return 0;

	  ret = vdb_write(&d->usage, sizeof(storage_t));
	  if (!ret)
		 return 0;

	  ret = vdb_write(&d->count, sizeof(storage_t));
	  if (!ret)
		 return 0;

	  num++;
   }

#ifdef ASSERT_DEBUG
   assert(num == domainlist_num);
#endif

   /*
	  Write users and directories
   */

   num = 0;

   for (u = userlist; u; u = u->next) {
#ifdef ASSERT_DEBUG
	  assert(u->user != NULL);
	  assert(*(u->user));
	  assert(u->home != NULL);
	  assert(*(u->home));
	  assert(u->domain != NULL);
	  assert(u->domain->domain != NULL);
	  assert(*(u->domain->domain));
#endif

	  /*
		 username
	  */

	  len = strlen(u->user);
	  if (len >= sizeof(l_user)) {
		 fprintf(stderr, "vdb_save: username too long: %s\n", u->user);
		 vdb_remove();
		 return 0;
	  }

	  memset(l_user, 0, sizeof(l_user));
	  memcpy(l_user, u->user, len);

	  ret = vdb_write(l_user, sizeof(l_user));
	  if (!ret)
		 return 0;

	  /*
		 domain
	  */

	  len = strlen(u->domain->domain);
	  if (len >= sizeof(l_domain)) {
		 fprintf(stderr, "vdb_save: domain too long: %s\n", u->domain->domain);
		 vdb_remove();
		 return 0;
	  }

	  memset(l_domain, 0, sizeof(l_domain));
	  memcpy(l_domain, u->domain->domain, len);

	  ret = vdb_write(l_domain, sizeof(l_domain));
	  if (!ret)
		 return 0;

	  /*
		 home directory
	  */

	  len = strlen(u->home);
	  if (len >= sizeof(l_path)) {
		 fprintf(stderr, "vdb_save: path too long: %s\n", u->home);
		 vdb_remove();
		 return 0;
	  }

	  memset(l_path, 0, sizeof(l_path));
	  memcpy(l_path, u->home, len);

	  ret = vdb_write(l_path, sizeof(l_path));
	  if (!ret)
		 return 0;

	  /*
		 vqpasswd structure
	  */

	  /*
		 pw:name
	  */

	  memset(l_user, 0, sizeof(l_user));

	  if (u->pw) {
		 len = strlen(u->pw->pw_name);
		 if (len >= sizeof(l_user)) {
			fprintf(stderr, "vdb_save: name too long: %s\n", u->pw->pw_name);
			vdb_remove();
			return 0;
		 }

		 memcpy(l_user, u->pw->pw_name, len);
	  }

	  ret = vdb_write(l_user, sizeof(l_user));
	  if (!ret)
		 return 0;

	  /*
		 pw:passwd
	  */

	  memset(l_pass, 0, sizeof(l_pass));

	  if (u->pw) {
		 len = strlen(u->pw->pw_passwd);
		 if (len >= sizeof(l_pass)) {
			fprintf(stderr, "vdb_save: passwd too long: %s\n", u->pw->pw_passwd);
			vdb_remove();
			return 0;
		 }

		 memcpy(l_pass, u->pw->pw_passwd, len);
	  }

	  ret = vdb_write(l_pass, sizeof(l_pass));
	  if (!ret)
		 return 0;

	  /*
		 pw:uid
	  */

	  ret = vdb_write(u->pw ? &u->pw->pw_uid : 0, sizeof(uid_t));
	  if (!ret)
		 return 0;

	  /*
		 pw:gid
	  */

	  ret = vdb_write(u->pw ? &u->pw->pw_gid : 0, sizeof(gid_t));
	  if (!ret)
		 return 0;

	  /*
		 pw:flags
	  */

	  ret = vdb_write(u->pw ? &u->pw->pw_flags : 0, sizeof(gid_t));
	  if (!ret)
		 return 0;

	  /*
		 pw:gecos
	  */

	  memset(l_gecos, 0, sizeof(l_gecos));

	  if (u->pw) {
		 len = strlen(u->pw->pw_gecos);
		 if (len >= sizeof(l_gecos)) {
			fprintf(stderr, "vdb_save: gecos too long: %s\n", u->pw->pw_gecos);
			vdb_remove();
			return 0;
		 }

		 memcpy(l_gecos, u->pw->pw_gecos, len);
	  }

	  ret = vdb_write(l_gecos, sizeof(l_gecos));
	  if (!ret)
		 return 0;

	  /*
		 pw:dir
	  */

	  memset(l_path, 0, sizeof(l_path));

	  if (u->pw) {
		 len = strlen(u->pw->pw_dir);
		 if (len >= sizeof(l_path)) {
			fprintf(stderr, "vdb_save: dir too long: %s\n", u->pw->pw_dir);
			vdb_remove();
			return 0;
		 }

		 memcpy(l_path, u->pw->pw_dir, len);
	  }

	  ret = vdb_write(l_path, sizeof(l_path));
	  if (!ret)
		 return 0;

	  /*
		 pw:shell
	  */

	  memset(l_path, 0, sizeof(l_path));

	  if (u->pw) {
		 len = strlen(u->pw->pw_shell);
		 if (len >= sizeof(l_path)) {
			fprintf(stderr, "vdb_save: shell too long: %s\n", u->pw->pw_shell);
			vdb_remove();
			return 0;
		 }

		 memcpy(l_path, u->pw->pw_shell, len);
	  }

	  ret = vdb_write(l_path, sizeof(l_path));
	  if (!ret)
		 return 0;

	  /*
		 pw:clear_passwd
	  */

	  memset(l_pass, 0, sizeof(l_pass));

	  if (u->pw) {
		 len = strlen(u->pw->pw_clear_passwd);
		 if (len >= sizeof(l_pass)) {
			fprintf(stderr, "vdb_save: clear passwd too long: %s\n", u->pw->pw_clear_passwd);
			vdb_remove();
			return 0;
		 }

		 memcpy(l_pass, u->pw->pw_clear_passwd, len);
	  }

	  ret = vdb_write(l_pass, sizeof(l_pass));
	  if (!ret)
		 return 0;

	  /*
		 userstore:stat
	  */

	  memset(&l_stat, 0, sizeof(l_stat));

	  if (u->userstore)
		 memcpy(&l_stat, &u->userstore->st, sizeof(struct stat));

	  ret = vdb_write(&l_stat, sizeof(l_stat));
	  if (!ret)
		 return 0;

	  /*
		 userstore:last_updated
	  */

	  l_time = 0;
	  if (u->userstore)
		 l_time = u->userstore->last_updated;

	  ret = vdb_write(&l_time, sizeof(l_time));
	  if (!ret)
		 return 0;

	  /*
		 userstore:time_taken
	  */

	  l_time = 0;
	  if (u->userstore)
		 l_time = u->userstore->time_taken;

	  ret = vdb_write(&l_time, sizeof(l_time));
	  if (!ret)
		 return 0;

	  /*
		 userstore:lastauth
	  */

	  l_time = 0;
	  if (u->userstore)
		 l_time = u->userstore->lastauth;

	  ret = vdb_write(&l_time, sizeof(l_time));
	  if (!ret)
		 return 0;

	  /*
		 userstore:usage
	  */

	  l_storage = 0;
	  if (u->userstore)
		 l_storage = u->userstore->usage;

	  ret = vdb_write(&l_storage, sizeof(l_storage));
	  if (!ret)
		 return 0;

	  /*
		 userstore:count
	  */

	  l_storage = 0;
	  if (u->userstore)
		 l_storage = u->userstore->count;

	  ret = vdb_write(&l_storage, sizeof(l_storage));
	  if (!ret)
		 return 0;

	  /*
		 userstore:num_directories
	  */
   
	  l_int = 0;
	  if (u->userstore)
		 l_int = u->userstore->num_directories;

	  ret = vdb_write(&l_int, sizeof(l_int));
	  if (!ret)
		 return 0;

	  /*
		 userstore:directories
	  */

	  for (i = 0; ((u->userstore) && (i < l_int)); i++) {
#ifdef ASSERT_DEBUG
		 assert(u->userstore->directory != NULL);
		 assert(u->userstore->directory[i] != NULL);
		 assert(u->userstore->directory[i]->directory != NULL);
		 assert(*(u->userstore->directory[i]->directory) != '\0');
#endif

		 /*
			directory:directory
		 */

		 len = strlen(u->userstore->directory[i]->directory);
		 if (len >= sizeof(l_path)) {
			fprintf(stderr, "vdb_write: path too long: %s\n", u->userstore->directory[i]->directory);
			vdb_remove();
			return 0;
		 }

		 memset(l_path, 0, sizeof(l_path));
		 memcpy(l_path, u->userstore->directory[i]->directory, len);

		 ret = vdb_write(l_path, sizeof(l_path));
		 if (!ret)
			return 0;

		 /*
			directory:last_update
		 */

		 ret = vdb_write(&u->userstore->directory[i]->last_update, sizeof(l_time));
		 if (!ret)
			return 0;

		 /*
			directory:stat
		 */

		 ret = vdb_write(&u->userstore->directory[i]->st, sizeof(struct stat));
		 if (!ret)
			return 0;

		 /*
			directory:usage
		 */

		 ret = vdb_write(&u->userstore->directory[i]->usage, sizeof(storage_t));
		 if (!ret)
			return 0;

		 /*
			directory:count
		 */

		 ret = vdb_write(&u->userstore->directory[i]->count, sizeof(storage_t));
		 if (!ret)
			return 0;
	  }
   }

   vdb_close();

   printf("vdb: wrote snapshot of %llu user(s) on %llu domain(s)\n",
		 header.num_users, header.num_domains);

   return 1;
}

/*
   Read data file
*/

int vdb_load(void)
{
   int ret = 0, j = 0, l_int = 0;
   vdb_header_t header;
   domain_t *d = NULL;
   user_t *u = NULL;
   storage_t i = 0, l_usage = 0, l_count = 0;
   time_t l_time = 0;
   struct stat l_stat;
   directory_t *di = NULL;
   char l_domain[DOMAIN_MAX_DOMAIN] = { 0 }, l_path[PATH_MAX] = { 0 }, l_user[USER_MAX_USERNAME] = { 0 },
		l_gecos[MAX_PW_GECOS] = { 0 }, l_pass[MAX_PW_PASS] = { 0 };

   if (vdb_database == NULL)
	  return 1;

   vdb_fd = open(vdb_database, O_RDONLY, 0600);
   if (vdb_fd == -1) {
	  if (errno != ENOENT) {
		 fprintf(stderr, "vdb_load: open(%s) failed: %d\n", vdb_database, errno);
		 return 0;
	  }

	  return 1;
   }

   /*
	  Read header
   */

   ret = vdb_read(&header, sizeof(header));
   if (!ret)
	  return 0;

   if (strncmp(header.id, VDB_HEADER_ID, sizeof(header.id))) {
	  vdb_close();
	  fprintf(stderr, "vdb_load: %s does not appear to be a vusaged datafile\n", vdb_database);
	  return 0;
   }

   if (header.version != 0x03) {
	  vdb_close();
	  fprintf(stderr, "vdb_load: cannot process version %d vusaged datafiles\n", header.version);
	  return 0;
   }

   /*
	  Begin processing
   */

   /*
	  Domains
   */

   for (i = 0; i < header.num_domains; i++) {
	  /*
		 <domain><usage><count>
	  */

	  ret = vdb_read(l_domain, sizeof(l_domain));
	  if (!ret)
		 return 0;

	  ret = vdb_read(&l_usage, sizeof(l_usage));
	  if (!ret)
		 return 0;

	  ret = vdb_read(&l_count, sizeof(l_count));
	  if (!ret)
		 return 0;

	  /*
		 Allocate domain
	  */

	  d = domain_load(l_domain);
	  if (d == NULL) {
		 fprintf(stderr, "vdb_load: domain_load failed\n");
		 vdb_close();
		 return 0;
	  }

#ifdef ASSERT_DEBUG
	  assert(d->usage == 0);
	  assert(d->count == 0);
#endif

	  /*
		 Restore saved data
	  */

	  d->usage = l_usage;
	  d->count = l_count;
   }

   /*
	  Users and directories
   */

   for (i = 0; i < header.num_users; i++) {
	  /*
		 username
	  */

	  ret = vdb_read(l_user, sizeof(l_user));
	  if (!ret)
		 return 0;

	  /*
		 domain
	  */

	  ret = vdb_read(l_domain, sizeof(l_domain));
	  if (!ret)
		 return 0;

	  /*
		 home directory
	  */

	  ret = vdb_read(l_path, sizeof(l_path));
	  if (!ret)
		 return 0;

	  /*
		 Allocate user
	  */

	  u = malloc(sizeof(user_t));
	  if (u == NULL) {
		 fprintf(stderr, "vdb_load: malloc failed\n");
		 vdb_close();
		 return 0;
	  }

	  memset(u, 0, sizeof(user_t));

	  u->user = strdup(l_user);
	  if (u->user == NULL) {
		 user_free(u);
		 fprintf(stderr, "vdb_load: strdup failed\n");
		 vdb_close();
		 return 0;
	  }

	  u->domain = domain_load(l_domain);
	  if (u->domain == NULL) {
		 user_free(u);
		 fprintf(stderr, "vdb_load: domain_load failed\n");
		 vdb_close();
		 return 0;
	  }

	  u->home = strdup(l_path);
	  if (u->home == NULL) {
		 user_free(u);
		 fprintf(stderr, "vdb_load: strdup failed\n");
		 vdb_close();
		 return 0;
	  }

	  /*
		 Load vqpasswd structure
	  */

	  u->pw = malloc(sizeof(struct vqpasswd));
	  if (u->pw == NULL) {
		 user_free(u);
		 fprintf(stderr, "vdb_load: malloc failed\n");
		 vdb_close();
		 return 0;
	  }

	  /*
		 pw:name
	  */

	  ret = vdb_read(l_user, sizeof(l_user));
	  if (!ret)
		 return 0;

	  u->pw->pw_name = strdup(l_user);
	  if (u->pw->pw_name == NULL) {
		 user_free(u);
		 fprintf(stderr, "vdb_load: strdup failed\n");
		 vdb_close();
		 return 0;
	  }
	  
	  /*
		 pw:passwd
	  */

	  ret = vdb_read(l_pass, sizeof(l_pass));
	  if (!ret) {
		 user_free(u);
		 fprintf(stderr, "vdb_load: vdb_read failed\n");
		 vdb_close();
		 return 0;
	  }

	  u->pw->pw_passwd = strdup(l_pass);
	  if (u->pw->pw_passwd == NULL) {
		 user_free(u);
		 fprintf(stderr, "vdb_load: strdup failed\n");
		 vdb_close();
		 return 0;
	  }
	  
	  /*
		 pw:uid
	  */

	  ret = vdb_read(&u->pw->pw_uid, sizeof(uid_t));
	  if (!ret) {
		 user_free(u);
		 fprintf(stderr, "vdb_load: vdb_read failed\n");
		 vdb_close();
		 return 0;
	  }

	  /*
		 pw:gid
	  */

	  ret = vdb_read(&u->pw->pw_gid, sizeof(gid_t));
	  if (!ret) {
		 user_free(u);
		 fprintf(stderr, "vdb_load: vdb_read failed\n");
		 vdb_close();
		 return 0;
	  }

	  /*
		 pw:flags
	  */

	  ret = vdb_read(&u->pw->pw_flags, sizeof(gid_t));
	  if (!ret) {
		 user_free(u);
		 fprintf(stderr, "vdb_load: vdb_read failed\n");
		 vdb_close();
		 return 0;
	  }

	  /*
		 pw:gecos
	  */

	  ret = vdb_read(l_gecos, sizeof(l_gecos));
	  if (!ret)
		 return 0;

	  u->pw->pw_gecos = strdup(l_gecos);
	  if (u->pw->pw_gecos == NULL) {
		 user_free(u);
		 fprintf(stderr, "vdb_load: strdup failed\n");
		 vdb_close();
		 return 0;
	  }

	  /*
		 pw:dir
	  */

	  ret = vdb_read(l_path, sizeof(l_path));
	  if (!ret)
		 return 0;

	  u->pw->pw_dir = strdup(l_path);
	  if (u->pw->pw_dir == NULL) {
		 user_free(u);
		 fprintf(stderr, "vdb_load: strdup failed\n");
		 vdb_close();
		 return 0;
	  }

	  /*
		 pw:shell
	  */

	  ret = vdb_read(l_path, sizeof(l_path));
	  if (!ret)
		 return 0;

	  u->pw->pw_shell = strdup(l_path);
	  if (u->pw->pw_shell == NULL) {
		 user_free(u);
		 fprintf(stderr, "vdb_load: strdup failed\n");
		 vdb_close();
		 return 0;
	  }

	  /*
		 pw:clear_passwd
	  */

	  ret = vdb_read(l_pass, sizeof(l_pass));
	  if (!ret) {
		 user_free(u);
		 fprintf(stderr, "vdb_load: vdb_read failed\n");
		 vdb_close();
		 return 0;
	  }

	  u->pw->pw_clear_passwd = strdup(l_pass);
	  if (u->pw->pw_clear_passwd == NULL) {
		 user_free(u);
		 fprintf(stderr, "vdb_load: strdup failed\n");
		 vdb_close();
		 return 0;
	  }

	  /*
		 Allocate userstore
	  */

	  u->userstore = malloc(sizeof(userstore_t));
	  if (u->userstore == NULL) {
		 user_free(u);
		 fprintf(stderr, "vdb_load: malloc failed\n");
		 vdb_close();
		 return 0;
	  }

	  memset(u->userstore, 0, sizeof(userstore_t));

	  u->userstore->path = strdup(u->home);
	  if (u->userstore->path == NULL) {
		 user_free(u);
		 fprintf(stderr, "vdb_load: strdup failed\n");
		 vdb_close();
		 return 0;
	  }

	  /*
		 userstore:stat
	  */

	  ret = vdb_read(&u->userstore->st, sizeof(l_stat));
	  if (!ret)
		 return 0;

	  /*
		 userstore:last_updated
	  */

	  ret = vdb_read(&u->userstore->last_updated, sizeof(time_t));
	  if (!ret)
		 return 0;

	  /*
		 userstore:time_taken
	  */

	  ret = vdb_read(&u->userstore->time_taken, sizeof(time_t));
	  if (!ret)
		 return 0;

	  /*
		 userstore:lastauth
	  */

	  ret = vdb_read(&u->userstore->lastauth, sizeof(time_t));
	  if (!ret)
		 return 0;

	  /*
		 userstore:usage
	  */

	  ret = vdb_read(&u->userstore->usage, sizeof(storage_t));
	  if (!ret)
		 return 0;

	  /*
		 userstore:count
	  */

	  ret = vdb_read(&u->userstore->count, sizeof(storage_t));
	  if (!ret)
		 return 0;

	  /*
		 userstore:num_directories
	  */

	  ret = vdb_read(&l_int, sizeof(l_int));
	  if (!ret)
		 return 0;

	  /*
		 userstore:directories
	  */

	  for (j = 0; j < l_int; j++) {
		 /*
			directory:directory
		 */

		 ret = vdb_read(l_path, sizeof(l_path));
		 if (!ret)
			return 0;

		 di = directory_alloc(l_path);
		 if (di == NULL) {
			vdb_close();
			fprintf(stderr, "vdb_load: directory_alloc failed\n");
			return 0;
		 }

		 /*
			directory:last_update
		 */

		 ret = vdb_read(&di->last_update, sizeof(time_t));
		 if (!ret) {
			directory_free(di);
			return 0;
		 }

		 /*
			directory:stat
		 */

		 ret = vdb_read(&di->st, sizeof(struct stat));
		 if (!ret) {
			directory_free(di);
			return 0;
		 }

		 /*
			directory:usage
		 */

		 ret = vdb_read(&di->usage, sizeof(storage_t));
		 if (!ret) {
			directory_free(di);
			return 0;
		 }

		 /*
			directory:count
		 */

		 ret = vdb_read(&di->count, sizeof(storage_t));
		 if (!ret) {
			directory_free(di);
			return 0;
		 }

		 /*
			Add to userstore list
		 */

		 u->userstore->directory = (directory_t **)list_add((void *)u->userstore->directory, &(u->userstore->num_directories), di);
	  }

	  /*
		 Add user to userlist
	  */

	  ret = user_userlist_add(u);
	  if (!ret) {
		 vdb_close();
		 fprintf(stderr, "vdb_read: user_userlist_add failed\n");
		 return 0;
	  }
   }

   vdb_close();

   printf("vdb: loaded %llu user(s) on %llu domain(s)\n",
		 header.num_users, header.num_domains);

   return 1;
}

/*
   Write value to vdb descriptor
   If a failure occurs, back out and print error
*/

static inline int vdb_write(void *data, size_t len)
{
   ssize_t wret = 0;

#ifdef ASSERT_DEBUG
   assert(vdb_fd != -1);
#endif

   wret = write(vdb_fd, data, len);
   if (wret != len) {
	  vdb_remove();
	  fprintf(stderr, "vdb_write: write failed: %d/%d (%d)\n", wret, len, errno);
	  return 0;
   }

   return 1;
}

/*
   Read value from vdb descriptor
   If a failure occurs, back out and print error
*/

static inline int vdb_read(void *b, size_t len)
{
   ssize_t rret = 0;

#ifdef ASSERT_DEBUG
   assert(vdb_fd != -1);
#endif

   rret = read(vdb_fd, b, len);
   if (rret != len) {
	  vdb_close();
	  fprintf(stderr, "vdb_read: read failed: %d/%d (%d)\n", rret, len, errno);
	  return 0;
   }

   return 1;
}

/*
   Safely close database
*/

static inline int vdb_close(void)
{
   if (vdb_fd == -1)
	  return 1;

   close(vdb_fd);
   vdb_fd = -1;

   return 1;
}

/*
   Remove database file
*/

static inline int vdb_remove(void)
{
   if (vdb_database == NULL)
	  return 1;

   unlink(vdb_database);
   vdb_close();

   return 1;
}
