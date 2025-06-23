/* php_secex extension for PHP */

#ifndef PHP_PHP_SECEX_H
# define PHP_PHP_SECEX_H

extern zend_module_entry php_secex_module_entry;
# define phpext_php_secex_ptr &php_secex_module_entry

# define PHP_PHP_SECEX_VERSION "0.1.0"

# if defined(ZTS) && defined(COMPILE_DL_PHP_SECEX)
ZEND_TSRMLS_CACHE_EXTERN()
# endif

struct req_event{
    char *method;
    char *uri; 
};


/* Global state variables*/
ZEND_BEGIN_MODULE_GLOBALS(php_secex)
	int state;
	FILE* log_file;
    int dev_fd;
ZEND_END_MODULE_GLOBALS(php_secex)

ZEND_EXTERN_MODULE_GLOBALS(php_secex)

#ifdef ZTS
#define PHP_SECEX_G(v) ZEND_MODULE_GLOBALS_ACCESSOR(php_secex, v)
#else
#define PHP_SECEX_G(v) (php_secex_globals.v)
#endif
#endif	/* PHP_PHP_SECEX_H */
