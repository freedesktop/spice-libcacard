SUBDIRS = src
ACLOCAL_AMFLAGS = --install -I m4

lib_LTLIBRARIES = libcacard.la

libcacard_la_SOURCES =				\
	src/cac.c				\
	src/capcsc.h				\
	src/card_7816.c				\
	src/event.c				\
	src/glib-compat.h			\
	src/vcard.c				\
	src/vcard_emul_nss.c			\
	src/vcard_emul_type.c			\
	src/vcardt.c				\
	src/vcardt_internal.h			\
	src/vreader.c				\
	$(NULL)

if ENABLE_PCSC
libcacard_la_SOURCES += src/capcsc.c
endif

libcacard_includedir = $(includedir)/cacard
libcacard_include_HEADERS =			\
	src/cac.h				\
	src/card_7816.h				\
	src/card_7816t.h			\
	src/eventt.h				\
	src/libcacard.h				\
	src/vcard.h				\
	src/vcard_emul.h			\
	src/vcard_emul_type.h			\
	src/vcardt.h				\
	src/vevent.h				\
	src/vreader.h				\
	src/vreadert.h				\
	src/vscard_common.h			\
	$(NULL)

libcacard_la_LIBADD = $(CACARD_LIBS) $(PCSC_LIBS)
libcacard_la_LDFLAGS =					\
	-export-symbols $(srcdir)/src/libcacard.syms	\
	-no-undefined					\
	-version-info 0:0:0				\
	$(AM_LDFLAGS)					\
	$(NULL)

if OS_WIN32
libcacard_la_LIBADD += -lws2_32
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcacard.pc

bin_PROGRAMS = vscclient
vscclient_SOURCES = src/vscclient.c
vscclient_LDADD = libcacard.la $(GTHREAD_LIBS)
vscclient_CFLAGS = $(AM_CPPFLAGS) $(GTHREAD_CFLAGS)

if OS_WIN32
vscclient_CFLAGS += -D__USE_MINGW_ANSI_STDIO=1
endif

include $(srcdir)/build-aux/glib-tap.mk

test_programs = tests/libcacard
tests_libcacard_LDADD = libcacard.la $(GTHREAD_LIBS)

@CODE_COVERAGE_RULES@

AM_CPPFLAGS =					\
	-DG_LOG_DOMAIN=\"libcacard\"		\
	-DLIBCACARD_COMPILATION			\
	$(CACARD_CFLAGS)			\
	$(CODE_COVERAGE_CFLAGS)			\
	$(PCSC_CFLAGS)				\
	$(WARN_CFLAGS)				\
	-I$(srcdir)/src				\
	$(NULL)
AM_LDFLAGS = $(CODE_COVERAGE_LDFLAGS) $(WARN_LDFLAGS)

EXTRA_DIST +=					\
	NEWS					\
	README.md				\
	docs/libcacard.txt			\
	src/libcacard.syms			\
	build-aux/tap-driver.sh			\
	build-aux/tap-test			\
	tests/db/cert8.db                       \
	tests/db/key3.db                        \
	tests/db/secmod.db                      \
	$(NULL)

# aclocal will install pkg.m4 from pkg-config into m4
MAINTAINERCLEANFILES +=	$(srcdir)/m4/pkg.m4

MAINTAINERCLEANFILES +=					\
	$(GITIGNORE_MAINTAINERCLEANFILES_TOPLEVEL)	\
	$(GITIGNORE_MAINTAINERCLEANFILES_MAKEFILE_IN)	\
	$(GITIGNORE_MAINTAINERCLEANFILES_M4_LIBTOOL)

# see git-version-gen
dist-hook: gen-ChangeLog
	echo $(VERSION) > $(distdir)/.tarball-version

$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@

BUILT_SOURCES += $(top_srcdir)/.version
EXTRA_DIST +=				\
	$(top_srcdir)/.version		\
	build-aux/git-version-gen	\
	$(NULL)

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
