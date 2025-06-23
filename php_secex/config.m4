dnl config.m4 for extension php_secex

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary.

dnl If your extension references something external, use 'with':

dnl PHP_ARG_WITH([php_secex],
dnl   [for php_secex support],
dnl   [AS_HELP_STRING([--with-php_secex],
dnl     [Include php_secex support])])

dnl Otherwise use 'enable':

PHP_ARG_ENABLE([php_secex],
  [whether to enable php_secex support],
  [AS_HELP_STRING([--enable-php_secex],
    [Enable php_secex support])],
  [no])
if test "$PHP_PHP_SECEX" != "no"; then
  dnl Write more examples of tests here...

  dnl Remove this code block if the library does not support pkg-config.
  dnl PKG_CHECK_MODULES([LIBFOO], [foo])
  dnl PHP_EVAL_INCLINE($LIBFOO_CFLAGS)
  dnl PHP_EVAL_LIBLINE($LIBFOO_LIBS, PHP_SECEX_SHARED_LIBADD)

  dnl If you need to check for a particular library version using PKG_CHECK_MODULES,
  dnl you can use comparison operators. For example:
  dnl PKG_CHECK_MODULES([LIBFOO], [foo >= 1.2.3])
  dnl PKG_CHECK_MODULES([LIBFOO], [foo < 3.4])
  dnl PKG_CHECK_MODULES([LIBFOO], [foo = 1.2.3])

  dnl Remove this code block if the library supports pkg-config.
  dnl --with-php_secex -> check with-path
  dnl SEARCH_PATH="/usr/local /usr"     # you might want to change this
  dnl SEARCH_FOR="/include/php_secex.h"  # you most likely want to change this
  dnl if test -r $PHP_PHP_SECEX/$SEARCH_FOR; then # path given as parameter
  dnl   PHP_SECEX_DIR=$PHP_PHP_SECEX
  dnl else # search default path list
  dnl   AC_MSG_CHECKING([for php_secex files in default path])
  dnl   for i in $SEARCH_PATH ; do
  dnl     if test -r $i/$SEARCH_FOR; then
  dnl       PHP_SECEX_DIR=$i
  dnl       AC_MSG_RESULT(found in $i)
  dnl     fi
  dnl   done
  dnl fi
  dnl
  dnl if test -z "$PHP_SECEX_DIR"; then
  dnl   AC_MSG_RESULT([not found])
  dnl   AC_MSG_ERROR([Please reinstall the php_secex distribution])
  dnl fi

  dnl Remove this code block if the library supports pkg-config.
  dnl --with-php_secex -> add include path
  dnl PHP_ADD_INCLUDE($PHP_SECEX_DIR/include)

  dnl Remove this code block if the library supports pkg-config.
  dnl --with-php_secex -> check for lib and symbol presence
  dnl LIBNAME=PHP_SECEX # you may want to change this
  dnl LIBSYMBOL=PHP_SECEX # you most likely want to change this

  dnl If you need to check for a particular library function (e.g. a conditional
  dnl or version-dependent feature) and you are using pkg-config:
  dnl PHP_CHECK_LIBRARY($LIBNAME, $LIBSYMBOL,
  dnl [
  dnl   AC_DEFINE(HAVE_PHP_SECEX_FEATURE, 1, [ ])
  dnl ],[
  dnl   AC_MSG_ERROR([FEATURE not supported by your php_secex library.])
  dnl ], [
  dnl   $LIBFOO_LIBS
  dnl ])

  dnl If you need to check for a particular library function (e.g. a conditional
  dnl or version-dependent feature) and you are not using pkg-config:
  dnl PHP_CHECK_LIBRARY($LIBNAME, $LIBSYMBOL,
  dnl [
  dnl   PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $PHP_SECEX_DIR/$PHP_LIBDIR, PHP_SECEX_SHARED_LIBADD)
  dnl   AC_DEFINE(HAVE_PHP_SECEX_FEATURE, 1, [ ])
  dnl ],[
  dnl   AC_MSG_ERROR([FEATURE not supported by your php_secex library.])
  dnl ],[
  dnl   -L$PHP_SECEX_DIR/$PHP_LIBDIR -lm
  dnl ])
  dnl
  
  dnl PHP_SUBST(PHP_SECEX_SHARED_LIBADD)
  dnl CFLAGS=-Wl,probe_provider.o

  dnl In case of no dependencies
  AC_DEFINE(HAVE_PHP_SECEX, 1, [ Have php_secex support ])
  CFLAGS=-Wl,probe_provider.o

  PHP_NEW_EXTENSION(php_secex, php_secex.c, $ext_shared)
fi
