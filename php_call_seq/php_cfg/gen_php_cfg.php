<?php

declare(strict_types=1);

ini_set('memory_limit', '4096M');

use PhpParser\ParserFactory;

require __DIR__ . '/vendor/autoload.php';

$parser = new PHPCfg\Parser((new ParserFactory())->create(ParserFactory::PREFER_PHP7));

$declaration =  new \PHPCfg\Visitor\DeclarationFinder();
$calls = new \PHPCfg\Visitor\CallFinder();
$variables = new \PHPCfg\Visitor\VariableFinder();

$traverser = new \PHPCfg\Traverser();
$traverser->addVisitor($declaration);
$traverser->addVisitor($calls);
$traverser->addVisitor(new PHPCfg\Visitor\Simplifier());
$traverser->addVisitor($variables);

# $code = file_get_contents("./test_script.php");
# $script = $parser->parse($code, $phpFile);
# $traverser->traverse($script);
# $dumper = new \PHPCfg\Printer\Text();
# echo $dumper->printScript($script);
# exit(0);

function getPhpFiles($dir)
{
  $phpFiles = [];
  $items = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir));

  foreach ($items as $item) {
    if (!$item->isDir() && $item->getExtension() === 'php') {
      $phpFiles[] = $item->getRealPath();
    }
  }

  return $phpFiles;
}
$dir = "./wordpress/";
$phpFiles = getPhpFiles($dir);
// $static_no_init_pattern = '/static (\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*\s*,\s*)*\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*\s*;/';
foreach ($phpFiles as $phpFile) {
  echo "Exporting $phpFile\n";
  $code = file_get_contents($phpFile);
  // if (preg_match($static_no_init_pattern, $code)) {
  //   file_put_contents("skipped_files.txt", "Skipping $phpFile\n", FILE_APPEND);
  //   continue;
  // }

  $graph_file_name = substr($phpFile, strlen("/home/yslei/php_call_seq/php_cfg/"));
  $graph_file_name = str_replace('/', '.', $graph_file_name);
  $script = $parser->parse($code, $phpFile);
  $traverser->traverse($script);
  $dumper = new \PHPCfg\Printer\GraphViz();
  $graph = $dumper->printScript($script);
  try {
    $graph->export($type = 'dot_json', $file = 'new_script_cfg/' . $graph_file_name . '.dot_json');
  } catch (Exception $e) {
    file_put_contents("failed_files.txt", 'Caught exception when parsing' . $phpFile . $e->getMessage() . "\n", FILE_APPEND);
  }
}
