SUBDIRS = src
ACLOCAL_AMFLAGS = --install -I m4

lib_LTLIBRARIES = libcacard.la

libcacard_la_SOURCES =				\
	src/cac.c				\
	src/cac-aca.c				\
	src/cac-aca.h				\
	src/gp.c				\
	src/gp.h				\
	src/msft.c				\
	src/msft.h				\
	src/capcsc.h				\
	src/card_7816.c				\
	src/common.c				\
	src/common.h				\
	src/event.c				\
	src/glib-compat.h			\
	src/simpletlv.c				\
	src/simpletlv.h				\
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

include $(srcdir)/build-aux/glib-tap.mk

noinst_PROGRAMS += vscclient
vscclient_SOURCES = src/vscclient.c
vscclient_LDADD = libcacard.la $(GTHREAD_LIBS) $(PCSC_LIBS)
vscclient_CFLAGS = $(AM_CPPFLAGS) $(GTHREAD_CFLAGS) $(PCSC_CFLAGS)

if OS_WIN32
vscclient_CFLAGS += -D__USE_MINGW_ANSI_STDIO=1
endif

tests/softhsm2.conf:
	$(AM_V_GEN)(cd tests/ && $(abs_srcdir)/tests/setup-softhsm2.sh)

clean-local: code-coverage-clean
	rm -rf tests/hwdb tests/tokens tests/softhsm2.conf
distclean-local: code-coverage-dist-clean

EXTRA_DIST += tests/setup-softhsm2.sh

AM_TESTS_ENVIRONMENT += \
	SOFTHSM2_CONF=tests/softhsm2.conf

test_programs =					\
	tests/libcacard				\
	tests/simpletlv				\
	tests/hwtests				\
	$(NULL)

tests_libcacard_SOURCES =			\
	tests/common.c				\
	tests/common.h				\
	tests/libcacard.c			\
	$(NULL)
tests_libcacard_LDADD =				\
	libcacard.la				\
	src/common.lo				\
	src/simpletlv.lo			\
	$(NULL)

tests_simpletlv_LDADD =				\
	libcacard.la				\
	src/common.lo				\
	src/simpletlv.lo			\
	$(NULL)

tests_hwtests_SOURCES =				\
	tests/common.c				\
	tests/common.h				\
	tests/hwtests.c				\
	$(NULL)
tests_hwtests_LDADD =				\
	libcacard.la				\
	src/common.lo				\
	src/simpletlv.lo			\
	$(NULL)
tests_hwtests_DEPENDENCIES = tests/softhsm2.conf

include $(top_srcdir)/aminclude_static.am

AM_CPPFLAGS =					\
	-DG_LOG_DOMAIN=\"libcacard\"		\
	-DLIBCACARD_COMPILATION			\
	$(CACARD_CFLAGS)			\
	$(CODE_COVERAGE_CFLAGS)			\
	$(CODE_COVERAGE_CPPFLAGS)		\
	$(PCSC_CFLAGS)				\
	$(WARN_CFLAGS)				\
	-I$(srcdir)/src				\
	$(NULL)
AM_LDFLAGS = $(CODE_COVERAGE_LIBS) $(WARN_LDFLAGS)

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
	tests/cert.cfg				\
	$(NULL)

# aclocal will copy m4 files from pkg-config/autoconf-archives
MAINTAINERCLEANFILES +=	$(srcdir)/m4/pkg.m4
MAINTAINERCLEANFILES +=	$(srcdir)/m4/ax_*.m4

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
