/* 
   $Id$
   Copyright (C) 2009 Inter7 Internet Technologies, Inc.
 
   This is a composite of deliverquota's maildirquota.h, maildirmisc.h, and 
   numlib.h.  I only consolidated them to keep this patch to vpopmail  a bit 
   less intrusive.
   -Bill Shupp
 */

#define QUOTA_WARN_PERCENT 90

/* I've removed pretty much the whole file execept for
   some public functions so as to not conflict with courier.
   I"ve made the courier functions static.
   - Brian Kolaci
*/
int readdomainquota(const char *dir, long *sizep, int *cntp);
int readuserquota(const char* dir, long *sizep, int *cntp);
int domain_over_maildirquota(const char *userdir);
int user_over_maildirquota(const char *dir, const char *quota);
int vmaildir_readquota(const char *dir,	const char *quota);

int maildir_addquota(const char *,	/* Pointer to the maildir */
	int,	/* Must be the int pointed to by 2nd arg to checkquota */
	const char *,	/* The quota */
	long,	/* +/- bytes */
	int);	/* +/- files */
