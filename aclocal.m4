# generated automatically by aclocal 1.13.4 -*- Autoconf -*-

# Copyright (C) 1996-2013 Free Software Foundation, Inc.

# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.

m4_ifndef([AC_CONFIG_MACRO_DIRS], [m4_defun([_AM_CONFIG_MACRO_DIRS], [])m4_defun([AC_CONFIG_MACRO_DIRS], [_AM_CONFIG_MACRO_DIRS($@)])])
# ===========================================================================
#       https://www.gnu.org/software/autoconf-archive/ax_perl_ext.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_PERL_EXT
#
# DESCRIPTION
#
#   Fetches the linker flags and C compiler flags for compiling and linking
#   Perl binary extensions.  The macro substitutes PERL_EXT_PREFIX,
#   PERL_EXT_INC, PERL_EXT_LIB, PERL_EXT_CPPFLAGS, PERL_EXT_LDFLAGS and
#   PERL_EXT_DLEXT variables if Perl executable was found.  It also checks
#   the same variables before trying to retrieve them from the Perl
#   configuration.
#
#     PERL_EXT_PREFIX: top-level perl installation path (--prefix)
#     PERL_EXT_INC: XS include directory
#     PERL_EXT_LIB: Perl extensions destination directory
#     PERL_EXT_CPPFLAGS: C preprocessor flags to compile extensions
#     PERL_EXT_LDFLAGS: linker flags to build extensions
#     PERL_EXT_DLEXT: extensions suffix for perl modules (e.g. ".so")
#
#   Examples:
#
#     AX_PERL_EXT
#     if test x"$PERL" = x; then
#        AC_ERROR(["cannot find Perl"])
#     fi
#
# LICENSE
#
#   Copyright (c) 2011 Stanislav Sedov <stas@FreeBSD.org>
#   Copyright (c) 2014 Thomas Klausner <tk@giga.or.at>
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are
#   met:
#
#   1. Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
#
#   2. Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in the
#   documentation and/or other materials provided with the distribution.
#
#   THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
#   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
#   PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
#   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
#   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
#   THE POSSIBILITY OF SUCH DAMAGE.

#serial 3

AC_DEFUN([AX_PERL_EXT],[

        #
        # Check if perl executable exists.
        #
        AC_PATH_PROGS(PERL, ["${PERL-perl}"], [])

        if test -n "$PERL" ; then

                #
                # Check for Perl prefix.
                #
                AC_ARG_VAR(PERL_EXT_PREFIX, [Perl PREFIX])
                AC_MSG_CHECKING([for Perl prefix])
                if test -z "$PERL_EXT_PREFIX" ; then
                        [PERL_EXT_PREFIX=`$PERL -MConfig -e 'print $Config{prefix};'`];
                fi
                AC_MSG_RESULT([$PERL_EXT_PREFIX])
                AC_SUBST(PERL_EXT_PREFIX)

                #
                # Check for Perl extensions include path.
                #
                AC_ARG_VAR(PERL_EXT_INC, [Directory to include XS headers from])
                AC_MSG_CHECKING([for Perl extension include path])
                if test -z "$PERL_EXT_INC" ; then
                        [PERL_EXT_INC=`$PERL -MConfig -e 'print $Config{archlibexp}, "/CORE";'`];
                fi
                AC_MSG_RESULT([$PERL_EXT_INC])
                AC_SUBST(PERL_EXT_INC)

                #
                # Check for the extensions target directory.
                #
                AC_ARG_VAR(PERL_EXT_LIB, [Directory to install perl files into])
                AC_MSG_CHECKING([for Perl extension target directory])
                if test -z "$PERL_EXT_LIB" ; then
                        [PERL_EXT_LIB=`$PERL -MConfig -e 'print $Config{sitearch};'`];
                fi
                AC_MSG_RESULT([$PERL_EXT_LIB])
                AC_SUBST(PERL_EXT_LIB)

                #
                # Check for Perl CPP flags.
                #
                AC_ARG_VAR(PERL_EXT_CPPFLAGS, [CPPFLAGS to compile perl extensions])
                AC_MSG_CHECKING([for Perl extensions C preprocessor flags])
                if test -z "$PERL_EXT_CPPFLAGS" ; then
                        [PERL_EXT_CPPFLAGS=`$PERL -MConfig -e 'print $Config{cppflags};'`];
                fi
                AC_MSG_RESULT([$PERL_EXT_CPPFLAGS])
                AC_SUBST(PERL_EXT_CPPFLAGS)

                #
                # Check for Perl extension link flags.
                #
                AC_ARG_VAR(PERL_EXT_LDFLAGS, [LDFLAGS to build perl extensions])
                AC_MSG_CHECKING([for Perl extensions linker flags])
                if test -z "$PERL_EXT_LDFLAGS" ; then
                        [PERL_EXT_LDFLAGS=`$PERL -MConfig -e 'print $Config{lddlflags};'`];
                fi
                # Fix LDFLAGS for OS X.  We don't want any -arch flags here, otherwise
                # linking will fail.  Also, OS X Perl LDFLAGS contains "-arch ppc" which
                # is not supported by XCode anymore.
                case "${host}" in
                *darwin*)
                        PERL_EXT_LDFLAGS=`echo ${PERL_EXT_LDFLAGS} | sed -e "s,-arch [[^ ]]*,,g"`
                        ;;
                esac
                AC_MSG_RESULT([$PERL_EXT_LDFLAGS])
                AC_SUBST(PERL_EXT_LDFLAGS)

                #
                # Check for Perl dynamic library extension.
                #
                AC_ARG_VAR(PERL_EXT_DLEXT, [Perl dynamic library extension])
                AC_MSG_CHECKING([for Perl dynamic library extension])
                if test -z "$PERL_EXT_DLEXT" ; then
                        [PERL_EXT_DLEXT=`$PERL -MConfig -e 'print ".", $Config{'dlext'};'`];
                fi
                AC_MSG_RESULT([$PERL_EXT_DLEXT])
                AC_SUBST(PERL_EXT_DLEXT)
        fi
])

# pkg.m4 - Macros to locate and utilise pkg-config.            -*- Autoconf -*-
# serial 1 (pkg-config-0.24)
# 
# Copyright © 2004 Scott James Remnant <scott@netsplit.com>.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
# As a special exception to the GNU General Public License, if you
# distribute this file as part of a program that contains a
# configuration script generated by Autoconf, you may include it under
# the same distribution terms that you use for the rest of that program.

# PKG_PROG_PKG_CONFIG([MIN-VERSION])
# ----------------------------------
AC_DEFUN([PKG_PROG_PKG_CONFIG],
[m4_pattern_forbid([^_?PKG_[A-Z_]+$])
m4_pattern_allow([^PKG_CONFIG(_(PATH|LIBDIR|SYSROOT_DIR|ALLOW_SYSTEM_(CFLAGS|LIBS)))?$])
m4_pattern_allow([^PKG_CONFIG_(DISABLE_UNINSTALLED|TOP_BUILD_DIR|DEBUG_SPEW)$])
AC_ARG_VAR([PKG_CONFIG], [path to pkg-config utility])
AC_ARG_VAR([PKG_CONFIG_PATH], [directories to add to pkg-config's search path])
AC_ARG_VAR([PKG_CONFIG_LIBDIR], [path overriding pkg-config's built-in search path])

if test "x$ac_cv_env_PKG_CONFIG_set" != "xset"; then
	AC_PATH_TOOL([PKG_CONFIG], [pkg-config])
fi
if test -n "$PKG_CONFIG"; then
	_pkg_min_version=m4_default([$1], [0.9.0])
	AC_MSG_CHECKING([pkg-config is at least version $_pkg_min_version])
	if $PKG_CONFIG --atleast-pkgconfig-version $_pkg_min_version; then
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no])
		PKG_CONFIG=""
	fi
fi[]dnl
])# PKG_PROG_PKG_CONFIG

# PKG_CHECK_EXISTS(MODULES, [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
#
# Check to see whether a particular set of modules exists.  Similar
# to PKG_CHECK_MODULES(), but does not set variables or print errors.
#
# Please remember that m4 expands AC_REQUIRE([PKG_PROG_PKG_CONFIG])
# only at the first occurence in configure.ac, so if the first place
# it's called might be skipped (such as if it is within an "if", you
# have to call PKG_CHECK_EXISTS manually
# --------------------------------------------------------------
AC_DEFUN([PKG_CHECK_EXISTS],
[AC_REQUIRE([PKG_PROG_PKG_CONFIG])dnl
if test -n "$PKG_CONFIG" && \
    AC_RUN_LOG([$PKG_CONFIG --exists --print-errors "$1"]); then
  m4_default([$2], [:])
m4_ifvaln([$3], [else
  $3])dnl
fi])

# _PKG_CONFIG([VARIABLE], [COMMAND], [MODULES])
# ---------------------------------------------
m4_define([_PKG_CONFIG],
[if test -n "$$1"; then
    pkg_cv_[]$1="$$1"
 elif test -n "$PKG_CONFIG"; then
    PKG_CHECK_EXISTS([$3],
                     [pkg_cv_[]$1=`$PKG_CONFIG --[]$2 "$3" 2>/dev/null`
		      test "x$?" != "x0" && pkg_failed=yes ],
		     [pkg_failed=yes])
 else
    pkg_failed=untried
fi[]dnl
])# _PKG_CONFIG

# _PKG_SHORT_ERRORS_SUPPORTED
# -----------------------------
AC_DEFUN([_PKG_SHORT_ERRORS_SUPPORTED],
[AC_REQUIRE([PKG_PROG_PKG_CONFIG])
if $PKG_CONFIG --atleast-pkgconfig-version 0.20; then
        _pkg_short_errors_supported=yes
else
        _pkg_short_errors_supported=no
fi[]dnl
])# _PKG_SHORT_ERRORS_SUPPORTED


# PKG_CHECK_MODULES(VARIABLE-PREFIX, MODULES, [ACTION-IF-FOUND],
# [ACTION-IF-NOT-FOUND])
#
#
# Note that if there is a possibility the first call to
# PKG_CHECK_MODULES might not happen, you should be sure to include an
# explicit call to PKG_PROG_PKG_CONFIG in your configure.ac
#
#
# --------------------------------------------------------------
AC_DEFUN([PKG_CHECK_MODULES],
[AC_REQUIRE([PKG_PROG_PKG_CONFIG])dnl
AC_ARG_VAR([$1][_CFLAGS], [C compiler flags for $1, overriding pkg-config])dnl
AC_ARG_VAR([$1][_LIBS], [linker flags for $1, overriding pkg-config])dnl

pkg_failed=no
AC_MSG_CHECKING([for $1])

_PKG_CONFIG([$1][_CFLAGS], [cflags], [$2])
_PKG_CONFIG([$1][_LIBS], [libs], [$2])

m4_define([_PKG_TEXT], [Alternatively, you may set the environment variables $1[]_CFLAGS
and $1[]_LIBS to avoid the need to call pkg-config.
See the pkg-config man page for more details.])

if test $pkg_failed = yes; then
   	AC_MSG_RESULT([no])
        _PKG_SHORT_ERRORS_SUPPORTED
        if test $_pkg_short_errors_supported = yes; then
	        $1[]_PKG_ERRORS=`$PKG_CONFIG --short-errors --print-errors --cflags --libs "$2" 2>&1`
        else 
	        $1[]_PKG_ERRORS=`$PKG_CONFIG --print-errors --cflags --libs "$2" 2>&1`
        fi
	# Put the nasty error message in config.log where it belongs
	echo "$$1[]_PKG_ERRORS" >&AS_MESSAGE_LOG_FD

	m4_default([$4], [AC_MSG_ERROR(
[Package requirements ($2) were not met:

$$1_PKG_ERRORS

Consider adjusting the PKG_CONFIG_PATH environment variable if you
installed software in a non-standard prefix.

_PKG_TEXT])[]dnl
        ])
elif test $pkg_failed = untried; then
     	AC_MSG_RESULT([no])
	m4_default([$4], [AC_MSG_FAILURE(
[The pkg-config script could not be found or is too old.  Make sure it
is in your PATH or set the PKG_CONFIG environment variable to the full
path to pkg-config.

_PKG_TEXT

To get pkg-config, see <http://pkg-config.freedesktop.org/>.])[]dnl
        ])
else
	$1[]_CFLAGS=$pkg_cv_[]$1[]_CFLAGS
	$1[]_LIBS=$pkg_cv_[]$1[]_LIBS
        AC_MSG_RESULT([yes])
	$3
fi[]dnl
])# PKG_CHECK_MODULES


# PKG_INSTALLDIR(DIRECTORY)
# -------------------------
# Substitutes the variable pkgconfigdir as the location where a module
# should install pkg-config .pc files. By default the directory is
# $libdir/pkgconfig, but the default can be changed by passing
# DIRECTORY. The user can override through the --with-pkgconfigdir
# parameter.
AC_DEFUN([PKG_INSTALLDIR],
[m4_pushdef([pkg_default], [m4_default([$1], ['${libdir}/pkgconfig'])])
m4_pushdef([pkg_description],
    [pkg-config installation directory @<:@]pkg_default[@:>@])
AC_ARG_WITH([pkgconfigdir],
    [AS_HELP_STRING([--with-pkgconfigdir], pkg_description)],,
    [with_pkgconfigdir=]pkg_default)
AC_SUBST([pkgconfigdir], [$with_pkgconfigdir])
m4_popdef([pkg_default])
m4_popdef([pkg_description])
]) dnl PKG_INSTALLDIR


# PKG_NOARCH_INSTALLDIR(DIRECTORY)
# -------------------------
# Substitutes the variable noarch_pkgconfigdir as the location where a
# module should install arch-independent pkg-config .pc files. By
# default the directory is $datadir/pkgconfig, but the default can be
# changed by passing DIRECTORY. The user can override through the
# --with-noarch-pkgconfigdir parameter.
AC_DEFUN([PKG_NOARCH_INSTALLDIR],
[m4_pushdef([pkg_default], [m4_default([$1], ['${datadir}/pkgconfig'])])
m4_pushdef([pkg_description],
    [pkg-config arch-independent installation directory @<:@]pkg_default[@:>@])
AC_ARG_WITH([noarch-pkgconfigdir],
    [AS_HELP_STRING([--with-noarch-pkgconfigdir], pkg_description)],,
    [with_noarch_pkgconfigdir=]pkg_default)
AC_SUBST([noarch_pkgconfigdir], [$with_noarch_pkgconfigdir])
m4_popdef([pkg_default])
m4_popdef([pkg_description])
]) dnl PKG_NOARCH_INSTALLDIR

