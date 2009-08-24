/*
 * vlimits.c
 * handle domain limits in both file format
 * Brian Kolaci <bk@galaxy.net>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include "config.h"
#include "vlimits.h"
#include "vpopmail.h"


void vdefault_limits (struct vlimits *limits)
{
    /* initialize structure */
    memset(limits, 0, sizeof(*limits));
    limits->maxpopaccounts = -1;
    limits->maxaliases = -1;
    limits->maxforwards = -1;
    limits->maxautoresponders = -1;
    limits->maxmailinglists = -1;
}

#ifndef ENABLE_MYSQL_LIMITS

#define TOKENS " :\t\n\r"

/* find/read the .qmailadmin-limits file */
int vget_limits(const char *domain, struct vlimits *limits)
{
    char buf[256];
    char mydomain[256];
    char dir[MAXPATHLEN];
    uid_t uid;
    gid_t gid;
    char * s1;
    char * s2;
    FILE * fs;

    vdefault_limits(limits);

    /* use copy of name as vget_assign may change it on us */
    strncpy(mydomain, domain, sizeof(mydomain));
    mydomain[255] = '\0';

    /* get filename */
    vget_assign(mydomain, dir, sizeof(dir), &uid, &gid);
    strncat(dir, "/.qmailadmin-limits", sizeof(dir));

    /* open file */
    if ((fs = fopen(dir, "r")) != NULL) {
        while (fgets(buf, sizeof(buf), fs) != NULL) {
            if ((s1 = strtok(buf, TOKENS)) == NULL)
                continue;

            if (!strcmp(s1, "maxpopaccounts")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->maxpopaccounts = atoi(s2);
            }

            if (!strcmp(s1, "maxaliases")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->maxaliases = atoi(s2);
            }

            if (!strcmp(s1, "maxforwards")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->maxforwards = atoi(s2);
            }

            if (!strcmp(s1, "maxautoresponders")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->maxautoresponders = atoi(s2);
            }

            if (!strcmp(s1, "maxmailinglists")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->maxmailinglists = atoi(s2);
            }

            if (!strcmp(s1, "quota")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->diskquota = atoi(s2);
            }

            if (!strcmp(s1, "maxmsgcount")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->maxmsgcount = atoi(s2);
            }

            if (!strcmp(s1, "default_quota")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->defaultquota = atoi(s2);
            }

            if (!strcmp(s1, "default_maxmsgcount")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->defaultmaxmsgcount = atoi(s2);
            }

            if (!strcmp(s1, "disable_pop")) {
                limits->disable_pop = 1;
            }

            if (!strcmp(s1, "disable_imap")) {
                limits->disable_imap = 1;
            }

            if (!strcmp(s1, "disable_dialup")) {
                limits->disable_dialup = 1;
            }

            if (!strcmp(s1, "disable_password_changing")) {
                limits->disable_passwordchanging = 1;
            }

            if (!strcmp(s1, "disable_external_relay")) {
                limits->disable_relay = 1;
            }

            if (!strcmp(s1, "disable_smtp")) {
                limits->disable_smtp = 1;
            }

            if (!strcmp(s1, "disable_webmail")) {
                limits->disable_webmail = 1;
            }

            if (!strcmp(s1, "perm_account")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->perm_account = atoi(s2) & VLIMIT_DISABLE_ALL;
            }

            if (!strcmp(s1, "perm_alias")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->perm_alias = atoi(s2) & VLIMIT_DISABLE_ALL;
            }

            if (!strcmp(s1, "perm_forward")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->perm_forward = atoi(s2) & VLIMIT_DISABLE_ALL;
            }

            if (!strcmp(s1, "perm_autoresponder")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->perm_autoresponder = atoi(s2) & VLIMIT_DISABLE_ALL;
            }

            if (!strcmp(s1, "perm_maillist")) {
                unsigned long perm;
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                perm = atol(s2);
                limits->perm_maillist = perm & VLIMIT_DISABLE_ALL;
                perm >>= VLIMIT_DISABLE_BITS;
                limits->perm_maillist_users = perm & VLIMIT_DISABLE_ALL;
                perm >>= VLIMIT_DISABLE_BITS;
                limits->perm_maillist_moderators = perm & VLIMIT_DISABLE_ALL;
            }

            if (!strcmp(s1, "perm_quota")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->perm_quota = atoi(s2) & VLIMIT_DISABLE_ALL;
            }

            if (!strcmp(s1, "perm_defaultquota")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->perm_defaultquota = atoi(s2) & VLIMIT_DISABLE_ALL;
            }
        }
        fclose(fs);
        chown(dir,uid,gid);
        chmod(dir, S_IRUSR|S_IWUSR);
    } else {
        return -1;
    }

    return 0;
}

int vset_limits(const char *domain, const struct vlimits *limits)
{
    char mydomain[256];
    char dir[256];
    uid_t uid;
    gid_t gid;
    FILE * fs;

    /* use copy of name as vget_assign may change it on us */
    strncpy(mydomain, domain, sizeof(mydomain));
    mydomain[255] = '\0';

    /* get filename */
    vget_assign(mydomain, dir, sizeof(dir), &uid, &gid);
    strncat(dir, "/.qmailadmin-limits", sizeof(dir));

    /* open file */
    if ((fs = fopen(dir, "w+")) != NULL) {
        fprintf(fs, "maxpopaccounts: %d\n", limits->maxpopaccounts);
        fprintf(fs, "maxaliases: %d\n", limits->maxaliases);
        fprintf(fs, "maxforwards: %d\n", limits->maxforwards);
        fprintf(fs, "maxautoresponders: %d\n", limits->maxautoresponders);
        fprintf(fs, "maxmailinglists: %d\n", limits->maxmailinglists);
        fprintf(fs, "quota: %d\n", limits->diskquota);
        fprintf(fs, "maxmsgcount: %d\n", limits->maxmsgcount);
        fprintf(fs, "default_quota: %d\n", limits->defaultquota);
        fprintf(fs, "default_maxmsgcount: %d\n", limits->defaultmaxmsgcount);
        if (limits->disable_pop)
            fprintf(fs, "disable_pop\n");
        if (limits->disable_imap)
            fprintf(fs, "disable_imap\n");
        if (limits->disable_dialup)
            fprintf(fs, "disable_dialup\n");
        if (limits->disable_passwordchanging)
            fprintf(fs, "disable_password_changing\n");
        if (limits->disable_webmail)
            fprintf(fs, "disable_webmail\n");
        if (limits->disable_relay)
            fprintf(fs, "disable_external_relay\n");
        if (limits->disable_smtp)
            fprintf(fs, "disable_smtp\n");
        fprintf(fs, "perm_account: %d\n", limits->perm_account);
        fprintf(fs, "perm_alias: %d\n", limits->perm_alias);
        fprintf(fs, "perm_forward: %d\n", limits->perm_forward);
        fprintf(fs, "perm_autoresponder: %d\n", limits->perm_autoresponder);
        fprintf(fs, "perm_maillist: %d\n", limits->perm_maillist);
        fprintf(fs, "perm_quota: %d\n", (limits->perm_quota)|(limits->perm_maillist_users<<VLIMIT_DISABLE_BITS)|(limits->perm_maillist_moderators<<(VLIMIT_DISABLE_BITS*2)));
        fprintf(fs, "perm_defaultquota: %d\n", limits->perm_defaultquota);
        fclose(fs);
    } else {
        fprintf(stderr, "vlimits: failed to open limits file (%d):  %s\n", errno, dir);
        return -1;
    }

    return 0;
}

int vdel_limits(const char *domain)
{
    char mydomain[256];
    char dir[256];
    uid_t uid;
    gid_t gid;

    /* use copy of name as vget_assign may change it on us */
    strncpy(mydomain, domain, sizeof(mydomain));
    mydomain[255] = '\0';

    /* get filename */
    vget_assign(mydomain, dir, sizeof(dir), &uid, &gid);
    strncat(dir, "/.qmailadmin-limits", sizeof(dir));
    return unlink(dir);
}

#endif
