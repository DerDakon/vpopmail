@SET_MAKE@

SUBDIRS=cdb

noinst_LIBRARIES=libvpopmail.a

COMMONSOURCES=vpopmail.c md5.c bigdir.c vauth.c file_lock.c vpalias.c
CONFIG_CLEAN_FILES=vauth.c

libvpopmail_a_SOURCES=$(COMMONSOURCES) 
libvpopmail_a_LIBADD =  cdb/*.o

vpopmailbindir=@vpopmaildir@/bin
vpopmailbin_PROGRAMS = vchkpw vdelivermail clearopensmtp vadddomain \
 vdeldomain vpasswd vadduser vdeluser vaddaliasdomain vsetuserquota \
 vpopbull vdeloldusers vmoduser valias vuserinfo vmkpasswd vipmap \
 vdominfo vconvert vqmaillocal vkill
	

vuserinfo_SOURCES = vuserinfo.c maildirquota.c
vuserinfo_LDADD = libvpopmail.a @auth_libs@

vdominfo_SOURCES = vdominfo.c
vdominfo_LDADD = libvpopmail.a @auth_libs@

vchkpw_SOURCES = vchkpw.c 
vchkpw_LDADD = libvpopmail.a @auth_libs@

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

DEFS=-I. @auth_inc@ 

install-data-local:
	$(mkinstalldirs)  $(DESTDIR)@vpopmaildir@/@domains_dir@
	$(mkinstalldirs)  $(DESTDIR)@vpopmaildir@/lib
	$(mkinstalldirs)  $(DESTDIR)@vpopmaildir@/include
	$(mkinstalldirs)  $(DESTDIR)@vpopmaildir@/doc
	$(mkinstalldirs)  $(DESTDIR)@vpopmaildir@/etc
	$(mkinstalldirs)  $(DESTDIR)@vpopmaildir@/doc/man_html
	$(mkinstalldirs)  $(DESTDIR)@vpopmaildir@/doc/doc_html

	cp libvpopmail.a  $(DESTDIR)@vpopmaildir@/lib
	chown root        $(DESTDIR)@vpopmaildir@/lib/libvpopmail.a
	chmod og-rw       $(DESTDIR)@vpopmaildir@/lib/libvpopmail.a

	cp vpopmail.h     $(DESTDIR)@vpopmaildir@/include
	cp config.h       $(DESTDIR)@vpopmaildir@/include
	cp config.h       $(DESTDIR)@vpopmaildir@/include/vpopmail_config.h
	cp vauth.h        $(DESTDIR)@vpopmaildir@/include
	cp doc/man_html/* $(DESTDIR)@vpopmaildir@/doc/man_html
	cp doc/doc_html/* $(DESTDIR)@vpopmaildir@/doc/doc_html

	chmod 755 $(DESTDIR)@vpopmaildir@
	chmod 755 $(DESTDIR)@vpopmaildir@/include
	chmod 755 $(DESTDIR)@vpopmaildir@/etc
	chmod 755 $(DESTDIR)@vpopmaildir@/doc
	chmod 755 $(DESTDIR)@vpopmaildir@/doc/man_html
	chmod 755 $(DESTDIR)@vpopmaildir@/doc/doc_html
	chmod 755 $(DESTDIR)@vpopmaildir@/bin
	chmod 750 $(DESTDIR)@vpopmaildir@/bin/vdeloldusers
	chmod 700 $(DESTDIR)@vpopmaildir@/@domains_dir@
	chmod 711 $(DESTDIR)@vpopmaildir@/bin/*
	chmod 444 $(DESTDIR)@vpopmaildir@/include/*
	chmod 444 $(DESTDIR)@vpopmaildir@/doc/doc_html/*

	chown root    $(DESTDIR)@vpopmaildir@/lib
	chmod og-rwxs $(DESTDIR)@vpopmaildir@/lib

	@echo "If the recursive chown is taking a long time"
	@echo "go ahead and break out of it by pressing control-C"
	@echo "this is the last stage of the install and can be skipped" 
	chown -R @vpopuser@  $(DESTDIR)@vpopmaildir@/include
	chgrp -R @vpopgroup@ $(DESTDIR)@vpopmaildir@/include
	chown -R @vpopuser@  $(DESTDIR)@vpopmaildir@/etc
	chgrp -R @vpopgroup@ $(DESTDIR)@vpopmaildir@/etc
	chown -R @vpopuser@  $(DESTDIR)@vpopmaildir@/bin
	chgrp -R @vpopgroup@ $(DESTDIR)@vpopmaildir@/bin
	chown -R @vpopuser@  $(DESTDIR)@vpopmaildir@/doc
	chgrp -R @vpopgroup@ $(DESTDIR)@vpopmaildir@/doc
	chown -R @vpopuser@  $(DESTDIR)@vpopmaildir@/@domains_dir@
	chgrp -R @vpopgroup@ $(DESTDIR)@vpopmaildir@/@domains_dir@

AUTOMAKE_OPTIONS = foreign no-dependencies

