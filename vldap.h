#ifndef VPOPMAIL_LDAP_H
#define VPOPMAIL_LDAP_H

#undef OLD_VLDAP

#define VLDAP_SERVER "localhost"
#define VLDAP_PORT LDAP_PORT
#define VLDAP_USER "cn=Manager, o=vpop"
#define VLDAP_PASSWORD "proba"
#define MAX_BUFF 500

#ifdef OLD_VLDAP
   #define VLDAP_BASEDN "ou=Subs, o=vpop"
#else
   #define VLDAP_BASEDN "ou=%s, o=vpop"
#endif

static char *vldap_attrs[] = {
  "name",
  "uid",
  "qmailGID",
  "qmailUID",
  "qmaildomain",
  "userPassword",
  "mailQuota",
  "mailMessageStore",  
  NULL
};
#endif
