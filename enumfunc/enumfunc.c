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

#include "zend_API.h"
#include "zend_hash.h"
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "ext/standard/info.h"
#include "php_enumfunc.h"
#include <dlfcn.h>
#define LOG_PATH "/opt/php-7.4/var/log/enumfunc.log"
/* For compatibility with older PHP versions */
#ifndef ZEND_PARSE_PARAMETERS_NONE
#define ZEND_PARSE_PARAMETERS_NONE()                                           \
  ZEND_PARSE_PARAMETERS_START(0, 0)                                            \
  ZEND_PARSE_PARAMETERS_END()
#endif

ZEND_DECLARE_MODULE_GLOBALS(enumfunc)

static int create_local_log_file() {

  ENUMFUNC_G(log_file) = fopen(LOG_PATH, "a+");
  if (ENUMFUNC_G(log_file) == NULL) {
    fprintf(stderr, "[create_local_log_file]: open log file failed with %d\n",
            errno);
    return -1;
  }
  return 0;
}

static int enum_func_name(zval *zv, int num_args, va_list args,
                          zend_hash_key *hash_key) {
  Dl_info info;
  zend_function *func = Z_PTR_P(zv);
  const char *func_name = ZSTR_VAL(func->common.function_name);
  dladdr(func->internal_function.handler, &info);
  uint64_t handler_addr = (uint64_t)func->internal_function.handler;
  fprintf(ENUMFUNC_G(log_file), "%50s\t%" PRIx64 "\n", func_name,
          handler_addr - (uint64_t)info.dli_fbase);
  return 0;
}

static int enum_class_and_method(zval *zv, int num_args, va_list args,
                                 zend_hash_key *hash_key) {
  zend_class_entry *ce = (zend_class_entry *)Z_PTR_P(zv);
  if ((ce->ce_flags & (ZEND_ACC_INTERFACE | ZEND_ACC_TRAIT)) == 0) {
    fprintf(ENUMFUNC_G(log_file), "CLASS\t %s\n", ZSTR_VAL(ce->name));
    zend_hash_apply_with_arguments(&ce->function_table, enum_func_name, 0);
  }
  return ZEND_HASH_APPLY_KEEP;
}

PHP_FUNCTION(enum_func_details) {
  zend_hash_apply_with_arguments(EG(function_table), enum_func_name, 0);
  zend_hash_apply_with_arguments(EG(class_table), enum_class_and_method, 0);
  return;
}

PHP_GINIT_FUNCTION(enumfunc) {
  int ret = 0;
  ret = create_local_log_file();
  if (ret != 0) {
    fprintf(stderr, "[enumfunc] create local log file failed\n");
  }
}

PHP_MINIT_FUNCTION(enumfunc) { return SUCCESS; }

PHP_RINIT_FUNCTION(enumfunc) {
#if defined(ZTS) && defined(COMPILE_DL_ENUMFUNC)
  ZEND_TSRMLS_CACHE_UPDATE();
#endif

  return SUCCESS;
}

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(enumfunc) {
  php_info_print_table_start();
  php_info_print_table_header(2, "enumfunc support", "enabled");
  php_info_print_table_end();
}
/* }}} */
/* {{{ enumfunc_functions[]
 */
static const zend_function_entry enumfunc_functions[] = {
    PHP_FE(enum_func_details, NULL) PHP_FE_END};
/* }}} */

/* {{{ enumfunc_module_entry
 */
zend_module_entry enumfunc_module_entry = {
    STANDARD_MODULE_HEADER,
    "enumfunc",           /* Extension name */
    enumfunc_functions,   /* zend_function_entry */
    NULL,                 /* PHP_MINIT - Module initialization */
    NULL,                 /* PHP_MSHUTDOWN - Module shutdown */
    PHP_RINIT(enumfunc),  /* PHP_RINIT - Request initialization */
    NULL,                 /* PHP_RSHUTDOWN - Request shutdown */
    PHP_MINFO(enumfunc),  /* PHP_MINFO - Module info */
    PHP_ENUMFUNC_VERSION, /* Version */
    PHP_MODULE_GLOBALS(enumfunc),
    PHP_GINIT(enumfunc),
    NULL,
    NULL,
    STANDARD_MODULE_PROPERTIES_EX};
/* }}} */

#ifdef COMPILE_DL_ENUMFUNC
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif
ZEND_GET_MODULE(enumfunc)
#endif
