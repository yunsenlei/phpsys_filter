--TEST--
enumfunc_test2() Basic test
--SKIPIF--
<?php
if (!extension_loaded('enumfunc')) {
	echo 'skip';
}
?>
--FILE--
<?php
var_dump(enumfunc_test2());
var_dump(enumfunc_test2('PHP'));
?>
--EXPECT--
string(11) "Hello World"
string(9) "Hello PHP"
