/* php_secex extension for PHP */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "zend_API.h"
#include "SAPI.h"
#include "php.h"
#include "php_streams.h"
#include "ext/standard/info.h"
#include "Zend/zend_dtrace.h"
#include "php_php_secex.h"
#include "probe_provider.h"

#include <fcntl.h>

/* For compatibility with older PHP versions */
#ifndef ZEND_PARSE_PARAMETERS_NONE
#define ZEND_PARSE_PARAMETERS_NONE() \
	ZEND_PARSE_PARAMETERS_START(0, 0) \
	ZEND_PARSE_PARAMETERS_END()
#endif
ZEND_DECLARE_MODULE_GLOBALS(php_secex)
#define SAFE_FILENAME(f) ((f)?(f):"-")
#define LOCAL_LOG_PATH "/opt/php-7.4/var/log/php_secex.log"

static void (*original_zend_execute_internal)(zend_execute_data *execute_data, zval *return_value);
void secex_execute_internal(zend_execute_data *execute_data, zval *return_value);

static inline const char *secex_get_executed_filename(void)
{
        zend_execute_data *ex = EG(current_execute_data);

        while (ex && (!ex->func || !ZEND_USER_CODE(ex->func->type))) {
                ex = ex->prev_execute_data;
        }
        if (ex) {
                return ZSTR_VAL(ex->func->op_array.filename);
        } else {
                return zend_get_executed_filename();
        }
}


void secex_execute_internal(zend_execute_data *execute_data, zval *return_value){
	int lineno;
    const char *filename = NULL, *funcname = NULL;

	lineno  = zend_get_executed_lineno();
	filename = secex_get_executed_filename();
	funcname = get_active_function_name();

	if(filename != NULL && funcname != NULL){
		SECEX_FUNCTION_EXECUTE(filename, funcname, lineno);
	}
	else{
		fprintf(PHP_SECEX_G(log_file), "empty filenamd or functname\n");
	}

	original_zend_execute_internal(execute_data, return_value);
}

static int init_local_log_file(){
	PHP_SECEX_G(log_file) = fopen(LOCAL_LOG_PATH, "a+");
	if(PHP_SECEX_G(log_file) == NULL){
		fprintf(stderr, "[init_local_log_file]: fopen failed with error%d\n", errno);
		return -1;
	}
	return 0;
}

int secex_open(){
    int ret = 0;
    ret = open("/dev/secex_ioctl", O_RDWR);
    if(ret == -1){
        fprintf(stderr, "[secex_open]: open failed with errno %d\n", errno);
        return -1;
    }
    return ret;
}


PHP_GINIT_FUNCTION(php_secex)
{
	int ret = 0;

	/* set 0 initialize some setting related globals */
	php_secex_globals->state = 1;
	ret = init_local_log_file();
	if(ret != 0){
		fprintf(stderr, "failed to create local log file\n");
	}

}

PHP_RINIT_FUNCTION(php_secex)
{
#if defined(ZTS) && defined(COMPILE_DL_PHP_SECEX)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif
	
	SECEX_REQUEST_STARTUP(SAFE_FILENAME(SG(request_info).path_translated), SAFE_FILENAME(SG(request_info).request_uri), SAFE_FILENAME(SG(request_info).request_method));

	return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(php_secex){

	SECEX_REQUEST_SHUTDOWN();

	return SUCCESS;
}


PHP_MINFO_FUNCTION(php_secex)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "php_secex support", "enabled");
	php_info_print_table_end();
}

PHP_MINIT_FUNCTION(php_secex){
	original_zend_execute_internal = dtrace_execute_internal;
    zend_execute_internal = secex_execute_internal;
	return SUCCESS;
}



zend_module_entry php_secex_module_entry = {
	STANDARD_MODULE_HEADER,
	"php_secex",					/* Extension name */
	NULL,							/* zend_function_entry */
	PHP_MINIT(php_secex),			/* PHP_MINIT - Module initialization */
	NULL,						/* PHP_MSHUTDOWN - Module shutdown */
	PHP_RINIT(php_secex),			/* PHP_RINIT - Request initialization */
	PHP_RSHUTDOWN(php_secex),		/* PHP_RSHUTDOWN - Request shutdown */
	PHP_MINFO(php_secex),			/* PHP_MINFO - Module info */
	PHP_PHP_SECEX_VERSION,		    /* Version */
	PHP_MODULE_GLOBALS(php_secex),
	PHP_GINIT(php_secex),
	NULL,
	NULL,
	STANDARD_MODULE_PROPERTIES_EX
};

#ifdef COMPILE_DL_PHP_SECEX
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(php_secex)
#endif
