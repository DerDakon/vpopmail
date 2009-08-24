/* N.Fung <nfung@classY.jp>
   $Id: README.pgsql,v 1.2 2002/02/22 09:39:52 nfung Exp $
*/
2002/02/22

Notes on translating vmysql.c to vpgsql.c
* strings in SQL statements are enclosed with ' and not ".
* there is no "replace into" in pgsql.
* 'user' is a reserved column name! Changed 'user' to 'userid'.

To get it going become DBA of PostgreSQL server. Then:

1. /path/to/pgsql/bin/createuser vpopmail 
   
   (no need to grant vpopmail dba rights)

2. /path/to/pgsql/bin/createdb vpopmail

If you want to change "vpopmail", make sure you edit vpgsql.h and compile.

---ends---

