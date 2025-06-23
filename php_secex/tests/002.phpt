--TEST--
php_secex_test1() Basic test
--SKIPIF--
<?php
if (!extension_loaded('php_secex')) {
	echo 'skip';
}
?>
--FILE--
<?php
$ret = php_secex_test1();

var_dump($ret);
?>
--EXPECT--
The extension php_secex is loaded and working!
NULL
