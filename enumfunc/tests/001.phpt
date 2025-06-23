--TEST--
Check if enumfunc is loaded
--SKIPIF--
<?php
if (!extension_loaded('enumfunc')) {
	echo 'skip';
}
?>
--FILE--
<?php
echo 'The extension "enumfunc" is available';
?>
--EXPECT--
The extension "enumfunc" is available
