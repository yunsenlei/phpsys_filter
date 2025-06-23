--TEST--
enumfunc_test1() Basic test
--SKIPIF--
<?php
if (!extension_loaded('enumfunc')) {
	echo 'skip';
}
?>
--FILE--
<?php
$ret = enumfunc_test1();

var_dump($ret);
?>
--EXPECT--
The extension enumfunc is loaded and working!
NULL
