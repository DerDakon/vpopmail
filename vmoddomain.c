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
 */

/*
 * $Log: vmoddomain.c,v $
 * Revision 2.1  2009-01-28 11:25:17+05:30  Cprogrammer
 * program to modify .qmail-default
 *
 */
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "config.h"
#ifdef FILE_LOCKING
#include "file_lock.h"
#endif
#include "vpopmail.h"

#ifdef	lint
static char     sccsid[] = "$Id$";
#endif

static void     usage();
static int      get_options(int argc, char **argv, char **, char **);
int
main(int argc, char **argv)
{

	FILE           *fp;
	char           *domain = 0, *handler = 0;
	char            TheDir[MAX_BUFF], tmpbuf[MAX_BUFF], lockfile[MAX_BUFF];
	int             fd;
#ifdef FILE_LOCKING
	int             lockfd;
#endif
	uid_t           uid;
	gid_t           gid;

	if (get_options(argc, argv, &handler, &domain))
		return (1);
	if (!vget_assign(domain, TheDir, MAX_BUFF, &uid, &gid))
	{
		fprintf(stderr, "%s: domain does not exist\n", domain);
		return (1);
	}
	if (access(TheDir, F_OK))
	{
		if (r_mkdir(TheDir, uid, gid))
		{
			fprintf(stderr, "r_mkdir: %s: %s\n", TheDir, strerror(errno));
			return (1);
		}
	}
	if (chdir(TheDir))
	{
		fprintf(stderr, "chdir: %s: %s\n", TheDir, strerror(errno));
		return (1);
	}
	umask(VPOPMAIL_UMASK);
#ifdef FILE_LOCKING
	snprintf(lockfile, sizeof(lockfile), "%s/qmail-default.lock", TheDir);
	if ((lockfd = open(lockfile, O_WRONLY | O_CREAT, S_IRUSR|S_IWUSR)) < 0 )
	{
		fprintf(stderr, "could not open lock file %s\n", lockfile);
		return(VA_COULD_NOT_UPDATE_FILE);
	}
	if ( get_write_lock(lockfd) < 0 )
	{
		unlink(lockfile);
		fprintf(stderr, "get_write_lock: %s: %s\n", lockfile, strerror(errno));
		return (1);
	}
#endif
	snprintf(tmpbuf, MAX_BUFF, "%s/.qMail-default", TheDir);
	if ((fd = open(tmpbuf, O_CREAT|O_TRUNC|O_WRONLY, 0400)) == -1)
	{
		fprintf(stderr, "open: %s: %s\n", tmpbuf, strerror(errno));
#ifdef FILE_LOCKING
		unlock_lock(lockfd, 0, SEEK_SET, 0);
		close(lockfd);
		unlink(lockfile);
#endif
		return (1);
	}
	if (fchown(fd, uid, gid))
	{
		fprintf(stderr, "chown: %s: %s\n", tmpbuf, strerror(errno));
		close(fd);
		unlink(tmpbuf);
#ifdef FILE_LOCKING
		unlock_lock(lockfd, 0, SEEK_SET, 0);
		close(lockfd);
		unlink(lockfile);
#endif
		return (1);
	}
	if (!(fp = fdopen(fd, "w")))
	{
		fprintf(stderr, "fdopen: %s: %s\n", tmpbuf, strerror(errno));
		close(fd);
		unlink(tmpbuf);
#ifdef FILE_LOCKING
		unlock_lock(lockfd, 0, SEEK_SET, 0);
		close(lockfd);
		unlink(lockfile);
#endif
	}
	fprintf(fp, "| %s/vdelivermail '' %s\n", VPOPMAIL_DIR_BIN, handler);
	fclose(fp);
	if (rename(tmpbuf, ".qmail-default"))
	{
		fprintf(stderr, "rename: %s->.qmail-default: %s\n", tmpbuf, strerror(errno));
		unlink(tmpbuf);
#ifdef FILE_LOCKING
		unlock_lock(lockfd, 0, SEEK_SET, 0);
		close(lockfd);
		unlink(lockfile);
#endif
		return (1);
	}
#ifdef FILE_LOCKING
	unlock_lock(lockfd, 0, SEEK_SET, 0);
	close(lockfd);
	unlink(lockfile);
#endif
	return(0);
}

static void
usage()
{
	printf("Usage: vmoddomain [options] <domain>\n");
	printf("Options: -h <handler>\n");
	printf("Handlers:\n");
 	printf("          %s\n", DELETE_ALL);
 	printf("          %s\n", BOUNCE_ALL);
	printf("          /path/to/Maildir/\n");
	printf("          email@address\n");
	return;
}

static int
get_options(int argc, char **argv, char **handler, char **domain)
{
	int             c;

	*handler = *domain = 0;
	while ((c = getopt(argc, argv, "fh:")) != -1) 
	{
		switch (c)
		{
		case 'h':
			*handler = optarg;
			break;
		default:
			usage();
			return (1);
		}
	}
	if (!*handler)
	{
		usage();
		return (1);
	} else
	if (optind < argc)
		*domain = argv[optind++];
	else
	{
		usage();
		return (1);
	}
	/* Last case: the last parameter is a Maildir, an email address, ipaddress or hostname */
	if (!strncmp(*handler, BOUNCE_ALL, MAX_BUFF) || !strncmp(*handler, DELETE_ALL, MAX_BUFF))
		return (0);
	if (**handler == '/')
	{
		if (chdir (*handler))
		{
			fprintf(stderr, "chdir: %s: %s\n", *handler, strerror(errno));
			return (1);
		}
		if (access("new", F_OK) || access("cur", F_OK) || access("tmp", F_OK))
		{
			fprintf(stderr, "%s: not a Maildir\n", *handler);
			return (1);
		}
	} else /* email address */
	{
		if (!strchr(*handler, '@')) 
		{
			fprintf(stderr, "Invalid email address: %s\n", *handler);
			return (1);
		}
	}
	return(0);
}

 	  	 
