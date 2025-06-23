--TEST--
Check if php_secex is loaded
--SKIPIF--
<?php
if (!extension_loaded('php_secex')) {
	echo 'skip';
}
?>
--FILE--
<?php
echo 'The extension "php_secex" is available';
?>
--EXPECT--
The extension "php_secex" is available
