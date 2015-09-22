SUBDIRS = src
ACLOCAL_AMFLAGS = --install -I m4

lib_LTLIBRARIES = libcacard.la

libcacard_la_SOURCES =				\
	src/cac.c				\
	src/card_7816.c				\
	src/event.c				\
	src/glib-compat.h			\
	src/vcard.c				\
	src/vcard_emul_nss.c			\
	src/vcard_emul_type.c			\
	src/vcardt.c				\
	src/vreader.c				\
	$(NULL)

libcacard_includedir = $(includedir)/cacard
libcacard_include_HEADERS =			\
	src/cac.h				\
	src/card_7816.h				\
	src/card_7816t.h			\
	src/eventt.h				\
	src/vcard.h				\
	src/vcard_emul.h			\
	src/vcard_emul_type.h			\
	src/vcardt.h				\
	src/vcardt_internal.h			\
	src/vevent.h				\
	src/vreader.h				\
	src/vreadert.h				\
	src/vscard_common.h			\
	$(NULL)

libcacard_la_LIBADD = $(CACARD_LIBS)
libcacard_la_LDFLAGS =					\
	-export-symbols $(srcdir)/src/libcacard.syms	\
	-no-undefined					\
	-version-info 0:0:0				\
	$(WARN_LDFLAGS)
	$(NULL)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcacard.pc

bin_PROGRAMS = vscclient
vscclient_SOURCES = src/vscclient.c
vscclient_LDADD = libcacard.la $(CACARD_LIBS) $(GTHREAD_LIBS)
vscclient_CFLAGS = $(AM_CPPFLAGS) $(GTHREAD_CFLAGS)

AM_CPPFLAGS = $(CACARD_CFLAGS) $(WARN_CFLAGS)
EXTRA_DIST =					\
	README.md				\
	docs/libcacard.txt			\
	src/libcacard.syms			\
	$(NULL)

MAINTAINERCLEANFILES =					\
	$(GITIGNORE_MAINTAINERCLEANFILES_TOPLEVEL)	\
	$(GITIGNORE_MAINTAINERCLEANFILES_MAKEFILE_IN)	\
	$(GITIGNORE_MAINTAINERCLEANFILES_M4_LIBTOOL)

# see git-version-gen
dist-hook: gen-ChangeLog
	echo $(VERSION) > $(distdir)/.tarball-version

$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@

BUILT_SOURCES = $(top_srcdir)/.version
EXTRA_DIST += $(top_srcdir)/.version
gen-ChangeLog:
	@if test -d "$(srcdir)/.git"; then \
	  echo Generating ChangeLog... ; \
	  ( cd "$(srcdir)" \
	    && $(top_srcdir)/build-aux/missing --run git log --stat ) > ChangeLog.tmp \
	  && mv -f ChangeLog.tmp $(top_distdir)/ChangeLog \
	  || ( rm -f ChangeLog.tmp; \
	       echo Failed to generate ChangeLog >&2 ); \
	else \
	  echo A git checkout is required to generate a ChangeLog >&2; \
	fi

-include $(top_srcdir)/git.mk
