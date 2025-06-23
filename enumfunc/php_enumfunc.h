/*
   +----------------------------------------------------------------------+
   | PHP Version 7                                                        |
   +----------------------------------------------------------------------+
   | Copyright (c) The PHP Group                                          |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Author:  |
   +----------------------------------------------------------------------+
*/

#ifndef PHP_ENUMFUNC_H
#define PHP_ENUMFUNC_H

extern zend_module_entry enumfunc_module_entry;
#define phpext_enumfunc_ptr &enumfunc_module_entry

#define PHP_ENUMFUNC_VERSION "0.1.0"

ZEND_BEGIN_MODULE_GLOBALS(enumfunc)
FILE *log_file;
ZEND_END_MODULE_GLOBALS(enumfunc)

ZEND_EXTERN_MODULE_GLOBALS(enumfunc)
#if defined(ZTS) && defined(COMPILE_DL_ENUMFUNC)
ZEND_TSRMLS_CACHE_EXTERN()
#endif
#define ENUMFUNC_G(v) (enumfunc_globals.v)
#endif /* PHP_ENUMFUNC_H */
