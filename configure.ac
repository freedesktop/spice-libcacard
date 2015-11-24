AC_INIT([libcacard], [m4_esyscmd(build-aux/git-version-gen .tarball-version)],
                     [spice-devel@lists.freedesktop.org])
AX_IS_RELEASE([git-directory])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([foreign subdir-objects no-dist-gzip dist-xz])
AM_MAINTAINER_MODE([enable])
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

AC_CANONICAL_HOST
AC_MSG_CHECKING([for native Win32])
case "$host_os" in
     *mingw*|*cygwin*)
        os_win32=yes
        ;;
     *)
        os_win32=no
        ;;
esac
AC_MSG_RESULT([$os_win32])
AM_CONDITIONAL([OS_WIN32],[test "$os_win32" = "yes"])

AX_CHECK_ENABLE_DEBUG([yes],[DEBUG])

AC_PROG_CC
AM_PROG_CC_C_O
LT_INIT([disable-static win32-dll])
PKG_PROG_PKG_CONFIG

AX_COMPILER_FLAGS([WARN_CFLAGS],[WARN_LDFLAGS])
AX_CODE_COVERAGE()

PKG_CHECK_MODULES(CACARD, [glib-2.0 >= 2.22 nss >= 3.12.8])
PKG_CHECK_MODULES(GTHREAD, [gthread-2.0])

dnl === --enable-pcsc ==========================================================

AC_ARG_ENABLE([pcsc],
              AS_HELP_STRING([--disable-pcsc],
                             [do not build passthrough support]),,
              [enable_pcsc=auto])
if test "x$enable_pcsc" != "xno"; then
   PKG_CHECK_MODULES(PCSC, [libpcsclite], [have_pcsc=yes], [have_pcsc=no])
   if test "x$have_pcsc" = "xno" -a "x$enable_pcsc" = "xyes"; then
      AC_MSG_ERROR([pcsc support explicitly requested, but libpcsclite couldn't be found])
   fi
   if test "x$have_pcsc" = "xyes"; then
      enable_pcsc=yes
      AC_DEFINE([ENABLE_PCSC], 1, [pcsc support])
   else
      enable_pcsc=no
   fi
fi
AM_CONDITIONAL(ENABLE_PCSC, test "x$enable_pcsc" = "xyes")

GLIB_TESTS

AC_CONFIG_FILES([
Makefile
src/Makefile
libcacard.pc
])
AC_OUTPUT

AC_MSG_NOTICE([

libcacard - $VERSION

• Prefix: $prefix
• PCSC enabled: $enable_pcsc
• Code coverage: $enable_code_coverage
])
