/*
 * Copyright (C) 1999-2002 Inter7 Internet Technologies, Inc.
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

/* include files */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include <sys/uio.h>
#include "vlimits.h"
#include "maildirquota.h"
#include "config.h"

/* private functions - no name clashes with courier */
static char *makenewmaildirsizename(const char *, int *);
static int countcurnew(const char *, time_t *, off_t *, unsigned *);
static int countsubdir(const char *, const char *,
		time_t *, off_t *, unsigned *);
static int statcurnew(const char *, time_t *);
static int statsubdir(const char *, const char *, time_t *);
static int doaddquota(const char *, int, const char *, long, int, int);
static int docheckquota(const char *dir, int *maildirsize_fdptr,
	const char *quota_type, long xtra_size, int xtra_cnt, int *percentage);
static int docount(const char *, time_t *, off_t *, unsigned *);
static int maildir_checkquota(const char *dir, int *maildirsize_fdptr,
	const char *quota_type, long xtra_size, int xtra_cnt);
static int maildir_addquota(const char *dir, int maildirsize_fd,
	const char *quota_type, long maildirsize_size, int maildirsize_cnt);
static int maildir_safeopen(const char *path, int mode, int perm);
static char *str_pid_t(pid_t t, char *arg);
static char *str_time_t(time_t t, char *arg);
static int maildir_parsequota(const char *n, unsigned long *s);


#define  NUMBUFSIZE      60
#define	MDQUOTA_SIZE	'S'	/* Total size of all messages in maildir */
#define	MDQUOTA_BLOCKS	'B'	/* Total # of blocks for all messages in
				maildir -- NOT IMPLEMENTED */
#define	MDQUOTA_COUNT	'C'	/* Total number of messages in maildir */


/* bk: add domain limits functionality */
int domain_over_maildirquota(const char *userdir)
{
struct  stat    stat_buf;
int     ret_value = 0;
char	*domdir=(char *)malloc(strlen(userdir)+1);
char	*p;
char	domain[256];
unsigned long size = 0;
unsigned long maxsize = 0;
int	cnt = 0;
int	maxcnt = 0;
struct vlimits limits;

        if (fstat(0, &stat_buf) == 0 && S_ISREG(stat_buf.st_mode) &&
                stat_buf.st_size > 0)
        {

		/* locate the domain directory */
		strcpy(domdir, userdir);
		if ((p = strstr(domdir, "/Maildir/")) != NULL)
		{
			while (*(--p) != '/')
				;
			*(p+1) = '\0';
		}

		/* locate the domainname */
		while (*(--p) != '/')
			;
		snprintf(domain, sizeof(domain), "%s", ++p);
		if ((p = strchr(domain, '/')) != NULL)
			*p = '\0';

		/* get the domain quota */
		if (vget_limits(domain, &limits))
		{
			free(domdir);
			return 0;
		}
		/* convert from MB to bytes */
		maxsize = limits.diskquota * 1024 * 1024;
		maxcnt = limits.maxmsgcount;

		/* get the domain usage */
		if (readdomainquota(domdir, &size, &cnt))
		{
			free(domdir);
			return -1;
		}

		/* check if either quota (size/count) would be exceeded */
		if (maxsize > 0 && (size + stat_buf.st_size) > maxsize)
		{
			ret_value = 1;
		}
		else if (maxcnt > 0 && cnt >= maxcnt)
		{
			ret_value = 1;
		}
        }

	free(domdir);

        return(ret_value);
}

int readdomainquota(const char *dir, long *sizep, int *cntp)
{
int tries;
char	checkdir[256];
DIR	*dirp;
struct dirent *de;


	if (dir == NULL || sizep == NULL || cntp == NULL)
		return -1;

	*sizep = 0;
	*cntp = 0;

	dirp=opendir(dir);
	while (dirp && (de=readdir(dirp)) != 0)
	{
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;

		snprintf(checkdir, sizeof(checkdir), "%s%s/Maildir/", dir, de->d_name);
		tries = 5;
		while (tries-- && readuserquota(checkdir, sizep, cntp))
		{
			if (errno != EAGAIN)
				return -1;
			sleep(1);
		}
		if (tries <= 0)
			return -1;
	}
	if (dirp)
	{
#if	CLOSEDIR_VOID
		closedir(dirp);
#else
		if (closedir(dirp))
		{
			return (-1);
		}
#endif
	}

	return 0;
}

int readuserquota(const char* dir, long *sizep, int *cntp)
{
time_t	tm;
time_t	maxtime;
DIR	*dirp;
struct dirent *de;

	maxtime=0;

	if (countcurnew(dir, &maxtime, sizep, cntp))
	{
		return (-1);
	}

	dirp=opendir(dir);
	while (dirp && (de=readdir(dirp)) != 0)
	{
		if (countsubdir(dir, de->d_name, &maxtime, sizep, cntp))
		{
			closedir(dirp);
			return (-1);
		}
	}
	if (dirp)
	{
#if	CLOSEDIR_VOID
		closedir(dirp);
#else
		if (closedir(dirp))
		{
			return (-1);
		}
#endif
	}

	/* make sure nothing changed while calculating this... */
	tm=0;

	if (statcurnew(dir, &tm))
	{
		return (-1);
	}

	dirp=opendir(dir);
	while (dirp && (de=readdir(dirp)) != 0)
	{
		if (statsubdir(dir, de->d_name, &tm))
		{
			closedir(dirp);
			return (-1);
		}
	}
	if (dirp)
	{
#if	CLOSEDIR_VOID
		closedir(dirp);
#else
		if (closedir(dirp))
		{
			return (-1);
		}
#endif
	}

	if (tm != maxtime)	/* Race condition, someone changed something */
	{
		errno=EAGAIN;
		return (-1);
	}
	errno=0;

	return 0;
}

int user_over_maildirquota( const char *dir, const char *q)
{
struct  stat    stat_buf;
int     quotafd;
int     ret_value;

        if (fstat(0, &stat_buf) == 0 && S_ISREG(stat_buf.st_mode) &&
                stat_buf.st_size > 0 && *q)
        {
                if (maildir_checkquota(dir, &quotafd, q, stat_buf.st_size, 1)
                        && errno != EAGAIN)
                {
                        if (quotafd >= 0)       close(quotafd);
                        ret_value = 1;
                } else {
                        maildir_addquota(dir, quotafd, q, stat_buf.st_size, 1);
                        if (quotafd >= 0)       close(quotafd);
                        ret_value = 0;
                }
        } else {
                ret_value = 0;
        }

        return(ret_value);
}

void add_warningsize_to_quota( const char *dir, const char *q)
{
struct  stat    stat_buf;
int     quotafd;
char    quotawarnmsg[500];

        snprintf(quotawarnmsg, sizeof(quotawarnmsg), "%s/%s/.quotawarn.msg", VPOPMAILDIR, DOMAINS_DIR);

        if (stat(quotawarnmsg, &stat_buf) == 0 && S_ISREG(stat_buf.st_mode) &&
                stat_buf.st_size > 0 && *q)
        {
                maildir_checkquota(dir, &quotafd, q, stat_buf.st_size, 1);
                if (quotafd >= 0)       close(quotafd);
                maildir_addquota(dir, quotafd, q, 
                    stat_buf.st_size, 1);
                if (quotafd >= 0)       close(quotafd);
        }
}

/* Read the maildirsize file */

static int maildirsize_read(const char *filename,	/* The filename */
	int *fdptr,	/* Keep the file descriptor open */
	off_t *sizeptr,	/* Grand total of maildir size */
	unsigned *cntptr, /* Grand total of message count */
	unsigned *nlines, /* # of lines in maildirsize */
	struct stat *statptr)	/* The stats on maildirsize */
{
 char buf[5120];
 int f;
 char *p;
 unsigned l;
 int n;
 int first;

	if ((f=maildir_safeopen(filename, O_RDWR|O_APPEND, 0)) < 0)
		return (-1);
	p=buf;
	l=sizeof(buf);

	while (l)
	{
		n=read(f, p, l);
		if (n < 0)
		{
			close(f);
			return (-1);
		}
		if (n == 0)	break;
		p += n;
		l -= n;
	}
	if (l == 0 || fstat(f, statptr))	/* maildir too big */
	{
		close(f);
		return (-1);
	}

	*sizeptr=0;
	*cntptr=0;
	*nlines=0;
	*p=0;
	p=buf;
	first=1;
	while (*p)
	{
	long n=0;
	int c=0;
	char	*q=p;

		while (*p)
			if (*p++ == '\n')
			{
				p[-1]=0;
				break;
			}

		if (first)
		{
			first=0;
			continue;
		}
		sscanf(q, "%ld %d", &n, &c);
		*sizeptr += n;
		*cntptr += c;
		++ *nlines;
	}
	*fdptr=f;
	return (0);
}

static int qcalc(off_t s, unsigned n, const char *quota, int *percentage)
{
off_t i;
int	spercentage=0;
int	npercentage=0;

	errno=ENOSPC;
	while (quota && *quota)
	{
		int x=1;

		if (*quota < '0' || *quota > '9')
		{
			++quota;
			continue;
		}
		i=0;
		while (*quota >= '0' && *quota <= '9')
			i=i*10 + (*quota++ - '0');
		switch (*quota)	{
		default:
			if (i < s)
			{
				*percentage=100;
				return (-1);
			}

			/*
			** For huge quotas, over 20mb,
			** divide numerator & denominator by 1024 to prevent
			** an overflow when multiplying by 100
			*/

			x=1;
			if (i > 20000000) x=1024;

			spercentage = i ? (s/x) * 100 / (i/x):100;
			break;
		case 'C':

			if (i < n)
			{
				*percentage=100;
				return (-1);
			}

			/* Ditto */

			x=1;
			if (i > 20000000) x=1024;

			npercentage = i ? ((off_t)n/x) * 100 / (i/x):100;
			break;
		}
	}
	*percentage = spercentage > npercentage ? spercentage:npercentage;
	return (0);
}


static int maildir_checkquota(const char *dir,
	int *maildirsize_fdptr,
	const char *quota_type,
	long xtra_size,
	int xtra_cnt)
{
int	dummy;

	return (docheckquota(dir, maildirsize_fdptr, quota_type,
		xtra_size, xtra_cnt, &dummy));
}

int vmaildir_readquota(const char *dir, const char *quota_type)
{
int	percentage=0;
int	fd=-1;

	(void)docheckquota(dir, &fd, quota_type, 0, 0, &percentage);
	if (fd >= 0)
		close(fd);
	return (percentage);
}

static int docheckquota(const char *dir,
	int *maildirsize_fdptr,
	const char *quota_type,
	long xtra_size,
	int xtra_cnt,
	int *percentage)
{
char	*checkfolder=(char *)malloc(strlen(dir)+sizeof("/maildirfolder"));
char	*newmaildirsizename;
struct stat stat_buf;
int	maildirsize_fd;
off_t	maildirsize_size;
unsigned maildirsize_cnt;
unsigned maildirsize_nlines;
int	n;
time_t	tm;
time_t	maxtime;
DIR	*dirp;
struct dirent *de;

	if (checkfolder == 0)	return (-1);
	*maildirsize_fdptr= -1;
	strcat(strcpy(checkfolder, dir), "/maildirfolder");
	if (stat(checkfolder, &stat_buf) == 0)	/* Go to parent */
	{
		strcat(strcpy(checkfolder, dir), "/..");
		n=docheckquota(checkfolder, maildirsize_fdptr,
			quota_type, xtra_size, xtra_cnt, percentage);
		free(checkfolder);
		return (n);
	}
	if (!quota_type || !*quota_type)	return (0);

	strcat(strcpy(checkfolder, dir), "/maildirsize");
	time(&tm);
	if (maildirsize_read(checkfolder, &maildirsize_fd,
		&maildirsize_size, &maildirsize_cnt,
		&maildirsize_nlines, &stat_buf) == 0)
	{
		n=qcalc(maildirsize_size+xtra_size, maildirsize_cnt+xtra_cnt,
			quota_type, percentage);

		if (n == 0)
		{
			free(checkfolder);
			*maildirsize_fdptr=maildirsize_fd;
			return (0);
		}
		close(maildirsize_fd);

		if (maildirsize_nlines == 1 && tm < stat_buf.st_mtime + 15*60)
			return (n);
	}

	maxtime=0;
	maildirsize_size=0;
	maildirsize_cnt=0;

	if (countcurnew(dir, &maxtime, &maildirsize_size, &maildirsize_cnt))
	{
		free(checkfolder);
		return (-1);
	}

	dirp=opendir(dir);
	while (dirp && (de=readdir(dirp)) != 0)
	{
		if (countsubdir(dir, de->d_name, &maxtime, &maildirsize_size,
			&maildirsize_cnt))
		{
			free(checkfolder);
			closedir(dirp);
			return (-1);
		}
	}
	if (dirp)
	{
#if	CLOSEDIR_VOID
		closedir(dirp);
#else
		if (closedir(dirp))
		{
			free(checkfolder);
			return (-1);
		}
#endif
	}

	newmaildirsizename=makenewmaildirsizename(dir, &maildirsize_fd);
	if (!newmaildirsizename)
	{
		free(checkfolder);
		return (-1);
	}

	*maildirsize_fdptr=maildirsize_fd;

	if (doaddquota(dir, maildirsize_fd, quota_type, maildirsize_size,
		maildirsize_cnt, 1))
	{
		free(newmaildirsizename);
		unlink(newmaildirsizename);
		close(maildirsize_fd);
		*maildirsize_fdptr= -1;
		free(checkfolder);
		return (-1);
	}

	strcat(strcpy(checkfolder, dir), "/maildirsize");

	if (rename(newmaildirsizename, checkfolder))
	{
		free(checkfolder);
		unlink(newmaildirsizename);
		close(maildirsize_fd);
		*maildirsize_fdptr= -1;
	}
	free(checkfolder);
	free(newmaildirsizename);

	tm=0;

	if (statcurnew(dir, &tm))
	{
		close(maildirsize_fd);
		*maildirsize_fdptr= -1;
		return (-1);
	}

	dirp=opendir(dir);
	while (dirp && (de=readdir(dirp)) != 0)
	{
		if (statsubdir(dir, de->d_name, &tm))
		{
			close(maildirsize_fd);
			*maildirsize_fdptr= -1;
			closedir(dirp);
			return (-1);
		}
	}
	if (dirp)
	{
#if	CLOSEDIR_VOID
		closedir(dirp);
#else
		if (closedir(dirp))
		{
			close(maildirsize_fd);
			*maildirsize_fdptr= -1;
			return (-1);
		}
#endif
	}

	if (tm != maxtime)	/* Race condition, someone changed something */
	{
		errno=EAGAIN;
		return (-1);
	}

	return (qcalc(maildirsize_size+xtra_size, maildirsize_cnt+xtra_cnt,
		quota_type, percentage));
}

int	maildir_addquota(const char *dir, int maildirsize_fd,
	const char *quota_type, long maildirsize_size, int maildirsize_cnt)
{
	if (!quota_type || !*quota_type)	return (0);
	return (doaddquota(dir, maildirsize_fd, quota_type, maildirsize_size,
			maildirsize_cnt, 0));
}

static int doaddquota(const char *dir, int maildirsize_fd,
	const char *quota_type, long maildirsize_size, int maildirsize_cnt,
	int isnew)
{
union	{
	char	buf[100];
	struct stat stat_buf;
	} u;				/* Scrooge */
char	*newname2=0;
char	*newmaildirsizename=0;
struct	iovec	iov[3];
int	niov;
struct	iovec	*p;
int	n;

	niov=0;
	if ( maildirsize_fd < 0)
	{
		newname2=(char *)malloc(strlen(dir)+sizeof("/maildirfolder"));
		if (!newname2)	return (-1);
		strcat(strcpy(newname2, dir), "/maildirfolder");
		if (stat(newname2, &u.stat_buf) == 0)
		{
			strcat(strcpy(newname2, dir), "/..");
			n=doaddquota(newname2, maildirsize_fd, quota_type,
					maildirsize_size, maildirsize_cnt,
					isnew);
			free(newname2);
			return (n);
		}

		strcat(strcpy(newname2, dir), "/maildirsize");

		if ((maildirsize_fd=maildir_safeopen(newname2,
			O_RDWR|O_APPEND, 0644)) < 0)
		{
			newmaildirsizename=makenewmaildirsizename(dir, &maildirsize_fd);
			if (!newmaildirsizename)
			{
				free(newname2);
				return (-1);
			}

			maildirsize_fd=maildir_safeopen(newmaildirsizename,
				O_CREAT|O_RDWR|O_APPEND, 0644);

			if (maildirsize_fd < 0)
			{
				free(newname2);
				return (-1);
			}
			isnew=1;
		}
	}

	if (isnew)
	{
		(char *)iov[0].iov_base=(char *)quota_type;
		iov[0].iov_len=strlen(quota_type);
		(char *)iov[1].iov_base="\n";
		iov[1].iov_len=1;
		niov=2;
	}


	sprintf(u.buf, "%ld %d\n", maildirsize_size, maildirsize_cnt);
	(char *)iov[niov].iov_base=u.buf;
	iov[niov].iov_len=strlen(u.buf);

	p=iov;
	++niov;
	n=0;
	while (niov)
	{
		if (n)
		{
			if (n < p->iov_len)
			{
				(char *)p->iov_base=
					((char *)p->iov_base + n);
				p->iov_len -= n;
			}
			else
			{
				n -= p->iov_len;
				++p;
				--niov;
				continue;
			}
		}

		n=writev( maildirsize_fd, p, niov);

		if (n <= 0)
		{
			if (newname2)
			{
				close(maildirsize_fd);
				free(newname2);
			}
			return (-1);
		}
	}
	if (newname2)
	{
		close(maildirsize_fd);

		if (newmaildirsizename)
		{
			rename(newmaildirsizename, newname2);
			free(newmaildirsizename);
		}
		free(newname2);
	}
	return (0);
}

/* New maildirsize is built in the tmp subdirectory */

static char *makenewmaildirsizename(const char *dir, int *fd)
{
char	hostname[256];
struct	stat stat_buf;
time_t	t;
char	*p;
int i;

	hostname[0]=0;
	hostname[sizeof(hostname)-1]=0;
	gethostname(hostname, sizeof(hostname)-1);
	p=(char *)malloc(strlen(dir)+strlen(hostname)+130);
	if (!p)	return (0);

        /* do not hang forever */
	for (i=0;i<3;++i)
	{
	char	tbuf[NUMBUFSIZE];
	char	pbuf[NUMBUFSIZE];

		time(&t);
		strcat(strcpy(p, dir), "/tmp/");
		sprintf(p+strlen(p), "%s.%s_NeWmAiLdIrSiZe.%s",
			str_time_t(t, tbuf),
			str_pid_t(getpid(), pbuf), hostname);

		if (stat( (const char *)p, &stat_buf) < 0 &&
			(*fd=maildir_safeopen(p,
				O_CREAT|O_RDWR|O_APPEND, 0644)) >= 0)
			break;
		usleep(100);
	}
	return (p);
}

static int statcurnew(const char *dir, time_t *maxtimestamp)
{
char	*p=(char *)malloc(strlen(dir)+5);
struct	stat	stat_buf;

	if (!p)	return (-1);
	strcat(strcpy(p, dir), "/cur");
	if ( stat(p, &stat_buf) == 0 && stat_buf.st_mtime > *maxtimestamp)
		*maxtimestamp=stat_buf.st_mtime;
	strcat(strcpy(p, dir), "/new");
	if ( stat(p, &stat_buf) == 0 && stat_buf.st_mtime > *maxtimestamp)
		*maxtimestamp=stat_buf.st_mtime;
	free(p);
	return (0);
}

static int statsubdir(const char *dir, const char *subdir, time_t *maxtime)
{
char	*p;
int	n;

	if ( *subdir != '.' || strcmp(subdir, ".") == 0 ||
		strcmp(subdir, "..") == 0 || strcmp(subdir, ".Trash") == 0)
		return (0);

	p=(char *)malloc(strlen(dir)+strlen(subdir)+2);
	if (!p)	return (-1);
	strcat(strcat(strcpy(p, dir), "/"), subdir);
	n=statcurnew(p, maxtime);
	free(p);
	return (n);
}

static int countcurnew(const char *dir, time_t *maxtime,
	off_t *sizep, unsigned *cntp)
{
char	*p=(char *)malloc(strlen(dir)+5);
int	n;

	if (!p)	return (-1);
	strcat(strcpy(p, dir), "/new");
	n=docount(p, maxtime, sizep, cntp);
	if (n == 0)
	{
		strcat(strcpy(p, dir), "/cur");
		n=docount(p, maxtime, sizep, cntp);
	}
	free(p);
	return (n);
}

static int countsubdir(const char *dir, const char *subdir, time_t *maxtime,
	off_t *sizep, unsigned *cntp)
{
char	*p;
int	n;

	if ( *subdir != '.' || strcmp(subdir, ".") == 0 ||
		strcmp(subdir, "..") == 0 || strcmp(subdir, ".Trash") == 0)
		return (0);

	p=(char *)malloc(strlen(dir)+strlen(subdir)+2);
	if (!p)	return (2);
	strcat(strcat(strcpy(p, dir), "/"), subdir);
	n=countcurnew(p, maxtime, sizep, cntp);
	free(p);
	return (n);
}

static int docount(const char *dir, time_t *dirstamp,
	off_t *sizep, unsigned *cntp)
{
struct	stat	stat_buf;
char	*p;
DIR	*dirp;
struct dirent *de;
unsigned long	s;

	if (stat(dir, &stat_buf))	return (0);	/* Ignore */
	if (stat_buf.st_mtime > *dirstamp)	*dirstamp=stat_buf.st_mtime;
	if ((dirp=opendir(dir)) == 0)	return (0);
	while ((de=readdir(dirp)) != 0)
	{
	const char *n=de->d_name;

		if (*n == '.')	continue;

		/* PATCH - do not count msgs marked as deleted */

		for ( ; *n; n++)
		{
			if (n[0] != ':' || n[1] != '2' ||
				n[2] != ',')	continue;
			n += 3;
			while (*n >= 'A' && *n <= 'Z')
			{
				if (*n == 'T')	break;
				++n;
			}
			break;
		}
		if (*n == 'T')	continue;
		n=de->d_name;


		if (maildir_parsequota(n, &s) == 0)
			stat_buf.st_size=s;
		else
		{
			p=(char *)malloc(strlen(dir)+strlen(n)+2);
			if (!p)
			{
				closedir(dirp);
				return (-1);
			}
			strcat(strcat(strcpy(p, dir), "/"), n);
			if (stat(p, &stat_buf))
			{
				free(p);
				continue;
			}
			free(p);
		}
		*sizep += stat_buf.st_size;
		++*cntp;
	}

#if	CLOSEDIR_VOID
	closedir(dirp);
#else
	if (closedir(dirp))
		return (-1);
#endif
	return (0);
}

int maildir_safeopen(const char *path, int mode, int perm)
{
struct  stat    stat1, stat2;

int     fd=open(path, mode
#ifdef  O_NONBLOCK
                        | O_NONBLOCK
#else
                        | O_NDELAY
#endif
                                , perm);

        if (fd < 0)     return (fd);
        if (fcntl(fd, F_SETFL, (mode & O_APPEND)) || fstat(fd, &stat1)
            || lstat(path, &stat2))
        {
                close(fd);
                return (-1);
        }

        if (stat1.st_dev != stat2.st_dev || stat1.st_ino != stat2.st_ino)
        {
                close(fd);
                errno=ENOENT;
                return (-1);
        }

        return (fd);
}

char *str_pid_t(pid_t t, char *arg)
{
char    buf[NUMBUFSIZE];
char    *p=buf+sizeof(buf)-1;

        *p=0;
        do
        {
                *--p= '0' + (t % 10);
                t=t / 10;
        } while(t);
        return (strcpy(arg, p));
}

char *str_time_t(time_t t, char *arg)
{
char    buf[NUMBUFSIZE];
char    *p=buf+sizeof(buf)-1;

        *p=0;
        do
        {
                *--p= '0' + (t % 10);
                t=t / 10;
        } while(t);
        return (strcpy(arg, p));
}

int maildir_parsequota(const char *n, unsigned long *s)
{
const char *o;
int     yes;

        if ((o=strrchr(n, '/')) == 0)   o=n;

        for (; *o; o++)
                if (*o == ':')  break;
        yes=0;
        for ( ; o >= n; --o)
        {
                if (*o == '/')  break;

                if (*o == ',' && o[1] == 'S' && o[2] == '=')
                {
                        yes=1;
                        o += 3;
                        break;
                }
        }
        if (yes)
        {
                *s=0;
                while (*o >= '0' && *o <= '9')
                        *s= *s*10 + (*o++ - '0');
                return (0);
        }
        return (-1);
}