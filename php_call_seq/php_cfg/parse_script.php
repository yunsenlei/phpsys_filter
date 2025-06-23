<?php

use function ast\parse_file;
use ast\Node;

class PhpAstNode implements JsonSerializable
{
  public string $nodename;
  public array $attrs = array();
  private \ast\Node $script_root_ast;
  private $namespace;

  private $classname;
  public function __construct($script_name)
  {
    $this->script_root_ast = parse_file($script_name, 70);
    if ($this->script_root_ast->kind != ast\AST_STMT_LIST) {
      echo "Script root not is not a statement list, abort parsing: ", "$script_name\n";
      return;
    }

    /** @var Node[] $stmt_list */
    $stmt_list = $this->script_root_ast->children;
    foreach ($stmt_list as $stmt) {
      if ($stmt->kind == ast\AST_NAMESPACE) {
        $this->namespace = $stmt->children['name'];
      } elseif ($stmt->kind == ast\AST_CLASS) {
        $this->classname = $stmt->children['name'];
        $class_impl = $stmt->children['stmts'];
        $this->parse_class_impl($class_impl);
      }
    }
    $this->nodename = rtrim($this->namespace . "\\" . $this->classname, '_');
    if (substr($this->nodename, 0, strlen("PHPCfg\\Op\\")) == "PHPCfg\\Op\\") {
      $this->nodename = strtr(substr(rtrim($this->namespace . "\\" . $this->classname, '_'), strlen("PHPCfg\\Op\\")), '\\', '_');
    } else {
      echo "Cannot obtain the expected name for the class: $this->namespace, $this->classname\n";
      return;
    }

    if ($this->nodename == "Expr_Include") {
      array_unshift($this->attrs, "type");
    } elseif ($this->nodename == "Expr_Param") {
      array_unshift($this->attrs, "declaredType");
    } elseif ($this->nodename == "Stmt_ClassMethod") {
      array_unshift($this->attrs, "flags");
    } elseif ($this->nodename == "Stmt_Property") {
      array_unshift($this->attrs, "flags", "declaredType");
    }
  }

  private function parse_class_impl(Node $class_impl)
  {
    /** @var Node[] $stmt_list */
    $stmt_list = $class_impl->children;
    foreach ($stmt_list as $stmt) {
      if ($stmt->kind != ast\AST_METHOD) continue;
      if ($stmt->children['name'] != "getVariableNames") continue;
      /** @var Node[] $method_impl */
      $method_impl = $stmt->children['stmts']->children;
      foreach ($method_impl as $ms) {
        if ($ms->kind != ast\AST_RETURN) continue;
        if ($ms->children['expr']->kind != ast\AST_ARRAY) {
          echo "Does not support parsing AST node type $ms->children['expr']->kind\n";
          return;
        }
        /** @var Node[] $node_attrs */
        $node_attrs = $ms->children['expr']->children;
        foreach ($node_attrs as $attr) {
          $attr_name = $attr->children['value'];
          if (is_string($attr_name)) {
            $this->attrs[] = $attr_name;
          } else {
            echo "Array element not a string, need further parsing\n";
          }
        }
      }
    }
  }

  public function jsonSerialize()
  {
    return [
      'nodename' => $this->nodename,
      'attrs' => $this->attrs,
    ];
  }
}


$expr_node_files = glob("./vendor/yunsenlei/php-cfg/lib/PHPCfg/Op/Expr" . '/*.php');
$expr_bin_op_node_files = glob("./vendor/yunsenlei/php-cfg/lib/PHPCfg/Op/Expr/BinaryOp" . '/*.php');
$expr_cast_node_files = glob("./vendor/yunsenlei/php-cfg/lib/PHPCfg/Op/Expr/Cast/" . "/*.php");
$iterator_node_files = glob("./vendor/yunsenlei/php-cfg/lib/PHPCfg/Op/Iterator" . '/*.php');
$stmt_node_files = glob("./vendor/yunsenlei/php-cfg/lib/PHPCfg/Op/Stmt" . '/*.php');
$terminal_node_files = glob("./vendor/yunsenlei/php-cfg/lib/PHPCfg/Op/Terminal" . '/*.php');
$type_node_files = glob("./vendor/yunsenlei/php-cfg/lib/PHPCfg/Op/Type" . '/*.php');
$node_list = array();

foreach ($expr_node_files as $f) {
  $node = new PhpAstNode($f);
  $node->attrs = array_merge(["line"], $node->attrs);
  $node_list[] = $node;
}

foreach ($expr_bin_op_node_files as $f) {
  $node = new PhpAstNode($f);
  $node->attrs = array_merge($node->attrs, ["left", "right", "result"]);
  $node->attrs = array_merge(["line"], $node->attrs);
  $node_list[] = $node;
}

foreach ($expr_cast_node_files as $f) {
  $node = new PhpAstNode($f);
  $node->attrs = array_merge($node->attrs, ["expr", "result"]);
  $node->attrs = array_merge(["line"], $node->attrs);
  $node_list[] = $node;
}
foreach ($iterator_node_files as $f) {
  $node = new PhpAstNode($f);
  $node->attrs = array_merge(["line"], $node->attrs);
  $node_list[] = $node;
}

foreach ($stmt_node_files as $f) {
  $node = new PhpAstNode($f);
  $node->attrs = array_merge(["line"], $node->attrs);
  $node_list[] = $node;
}

foreach ($terminal_node_files as $f) {
  $node = new PhpAstNode($f);
  $node->attrs = array_merge(["line"], $node->attrs);
  $node_list[] = $node;
}

foreach ($type_node_files as $f) {
  $node = new PhpAstNode($f);
  $node->attrs = array_merge(["line"], $node->attrs);
  $node_list[] = $node;
}

$ast_nodes = ["astnodes" => $node_list];

file_put_contents("php_ast_nodes.json", json_encode($ast_nodes), 0);
