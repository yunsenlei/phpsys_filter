--TEST--
php_secex_test2() Basic test
--SKIPIF--
<?php
if (!extension_loaded('php_secex')) {
	echo 'skip';
}
?>
--FILE--
<?php
var_dump(php_secex_test2());
var_dump(php_secex_test2('PHP'));
?>
--EXPECT--
string(11) "Hello World"
string(9) "Hello PHP"
