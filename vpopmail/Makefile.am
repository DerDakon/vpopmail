# Copyright (C) 1999-2003 Inter7 Internet Technologies, Inc.

@SET_MAKE@

SUBDIRS=cdb
OBJEXT=o

noinst_LIBRARIES=libvpopmail.a

COMMONSOURCES=vpopmail.c md5.c bigdir.c vauth.c file_lock.c vpalias.c seek.c vlimits.c maildirquota.c
CONFIG_CLEAN_FILES=vauth.c

INSTALL= @INSTALL@ -o @vpopuser@ -m 711 -g @vpopgroup@ 

MYSQLCONF=$(DESTDIR)@vpopmaildir@/etc/vpopmail.mysql
VLIMITS=$(DESTDIR)@vpopmaildir@/etc/vlimits.default

libvpopmail_a_SOURCES=$(COMMONSOURCES) 
libvpopmail_a_LIBADD =  cdb/*.o

vpopmailbindir=@vpopmaildir@/bin
vpopmailbin_PROGRAMS = vchkpw vdelivermail clearopensmtp vadddomain \
 vdeldomain vpasswd vadduser vdeluser vaddaliasdomain vsetuserquota \
 vpopbull vdeloldusers vmoduser valias vuserinfo vmkpasswd vipmap \
 vdominfo vconvert vqmaillocal vkill vmoddomlimits vchangepw
	
vuserinfo_SOURCES = vuserinfo.c maildirquota.c
vuserinfo_LDADD = libvpopmail.a @auth_libs@

vdominfo_SOURCES = vdominfo.c
vdominfo_LDADD = libvpopmail.a @auth_libs@

vchkpw_SOURCES = vchkpw.c md5.c hmac_md5.c
vchkpw_LDADD = libvpopmail.a @auth_libs@

vchangepw_SOURCES = vchangepw.c
vchangepw_LDADD = libvpopmail.a @auth_libs@

vdelivermail_SOURCES = vdelivermail.c maildirquota.c
vdelivermail_LDADD = libvpopmail.a @auth_libs@

vqmaillocal_SOURCES = vqmaillocal.c 
vqmaillocal_LDADD = libvpopmail.a @auth_libs@

vkill_SOURCES = vkill.c 
vkill_LDADD = libvpopmail.a @auth_libs@

clearopensmtp_SOURCES = clearopensmtp.c
clearopensmtp_LDADD = libvpopmail.a @auth_libs@

vadddomain_SOURCES = vadddomain.c 
vadddomain_LDADD = libvpopmail.a @auth_libs@

vdeldomain_SOURCES = vdeldomain.c 
vdeldomain_LDADD = libvpopmail.a @auth_libs@

vpasswd_SOURCES = vpasswd.c 
vpasswd_LDADD = libvpopmail.a @auth_libs@

vadduser_SOURCES = vadduser.c
vadduser_LDADD = libvpopmail.a  @auth_libs@

vdeluser_SOURCES = vdeluser.c 
vdeluser_LDADD = libvpopmail.a @auth_libs@

vaddaliasdomain_SOURCES = vaddaliasdomain.c 
vaddaliasdomain_LDADD = libvpopmail.a @auth_libs@

vsetuserquota_SOURCES = vsetuserquota.c 
vsetuserquota_LDADD = libvpopmail.a @auth_libs@

vpopbull_SOURCES = vpopbull.c 
vpopbull_LDADD = libvpopmail.a @auth_libs@

vdeloldusers_SOURCES = vdeloldusers.c 
vdeloldusers_LDADD = libvpopmail.a @auth_libs@

vconvert_SOURCES = vconvert.c 
vconvert_LDADD = libvpopmail.a  @auth_libs@

vmoduser_SOURCES = vmoduser.c 
vmoduser_LDADD = libvpopmail.a  @auth_libs@

valias_SOURCES = valias.c 
valias_LDADD = libvpopmail.a  @auth_libs@

vmkpasswd_SOURCES = vmkpasswd.c 
vmkpasswd_LDADD = libvpopmail.a  @auth_libs@

vipmap_SOURCES = vipmap.c 
vipmap_LDADD = libvpopmail.a  @auth_libs@

vmoddomlimits_SOURCES = vmoddomlimits.c
vmoddomlimits_LDADD = libvpopmail.a  @auth_libs@

DEFS=-I. @auth_inc@ 

install-exec-am:
	for d in bin doc etc include lib ; do \
	  if test ! -d $(DESTDIR)@vpopmaildir@/$$d; then \
	    $(INSTALL) -d -g @vpopgroup@ -m 0755 -o @vpopuser@ \
	      $(DESTDIR)@vpopmaildir@/$$d ; \
	  fi ; \
	done

install-data-local:
	$(INSTALL) -d -g @vpopgroup@ -m 0700 -o @vpopuser@ \
	  $(DESTDIR)@vpopmaildir@/@domains_dir@

	echo "-I@vpopmaildir@/include" > @vpopmaildir@/etc/inc_deps
	echo "-L@vpopmaildir@/lib -lvpopmail @auth_libs@ @LIBS@" > @vpopmaildir@/etc/lib_deps

	if test ! -r $(VLIMITS); then \
	  $(INSTALL) -o @vpopuser@ -m 0644 -g @vpopgroup@ \
	    vlimits.default $(VLIMITS); \
	fi
	if test "@USE_MYSQL@" = "1"; then \
	  if test ! -r $(MYSQLCONF); then \
	    echo "# MYSQL CONNECTION SETTINGS FOR VPOPMAIL" >> $(MYSQLCONF); \
	    echo "#" >> $(MYSQLCONF); \
	    echo "# Line 1 defines the connection to use for database reads," >> $(MYSQLCONF); \
	    echo "# Line 2 defines the connection to use for database updates/writes." >> $(MYSQLCONF); \
	    echo "#" >> $(MYSQLCONF); \
	    echo "# If you omit line 2, then the same settings will be" >> $(MYSQLCONF); \
	    echo "# used for both read and write." >> $(MYSQLCONF); \
	    echo "#" >> $(MYSQLCONF); \
	    echo "# settings for each line:" >> $(MYSQLCONF); \
	    echo "# host|port|user|password|database" >> $(MYSQLCONF); \
	    echo "#" >> $(MYSQLCONF); \
	    echo "localhost|0|root|secret|vpopmail" >> $(MYSQLCONF); \
	    echo "#" >> $(MYSQLCONF); \
	    echo "# Note:" >> $(MYSQLCONF); \
	    echo "#   The value of host may be either a hostname or an IP address." >> $(MYSQLCONF); \
	    echo "#   If host is 'localhost', then sockets (Unix) or named pipes (Windows)" >> $(MYSQLCONF); \
	    echo "#   will be used instead of TCP/IP to connect to the server."   >> $(MYSQLCONF); \
	  fi ; \
	  chown @vpopuser@  $(MYSQLCONF) ; \
	  chgrp @vpopgroup@ $(MYSQLCONF) ; \
	  chmod 0640        $(MYSQLCONF) ; \
	fi

	$(INSTALL) -o root -m 0644 \
	  libvpopmail.a $(DESTDIR)@vpopmaildir@/lib/libvpopmail.a

	$(INSTALL) -o root -m 0444 \
	  config.h $(DESTDIR)@vpopmaildir@/include/vpopmail_config.h

	$(INSTALL) -o root -m 0444 \
	  vpopmail.h config.h vauth.h vlimits.h \
	  $(DESTDIR)@vpopmaildir@/include/

	$(INSTALL) -d $(DESTDIR)@vpopmaildir@/doc/man_html
	$(INSTALL) -d $(DESTDIR)@vpopmaildir@/doc/doc_html
	$(INSTALL) -o @vpopuser@ -m 0444 -g @vpopgroup@ \
	  doc/man_html/*.* $(DESTDIR)@vpopmaildir@/doc/man_html/

	$(INSTALL) -o @vpopuser@ -m 0444 -g @vpopgroup@ \
	  doc/doc_html/*.* $(DESTDIR)@vpopmaildir@/doc/doc_html/

fix-priv:
	if test -r $(MYSQLCONF); then \
	  chown @vpopuser@  $(MYSQLCONF) ; \
	  chgrp @vpopgroup@ $(MYSQLCONF) ; \
	  chmod 0640        $(MYSQLCONF) ; \
	fi
	@echo "If the recursive chown is taking a long time"
	@echo "go ahead and break out of it by pressing control-C"
	@echo "this is the last stage of the install and can be skipped" 
	chmod 700 $(DESTDIR)@vpopmaildir@/@domains_dir@
	chown -R @vpopuser@  $(DESTDIR)@vpopmaildir@/@domains_dir@
	chgrp -R @vpopgroup@ $(DESTDIR)@vpopmaildir@/@domains_dir@

AUTOMAKE_OPTIONS = foreign no-dependencies

