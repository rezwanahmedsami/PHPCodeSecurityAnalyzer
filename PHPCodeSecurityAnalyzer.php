<?php
/*
    * MIT License
    *
    * Copyright (c) 2023 Rezwan Ahmed Sami
    *
    * Permission is hereby granted, free of charge, to any person obtaining a copy
    * of this software and associated documentation files (the "Software"), to deal
    * in the Software without restriction, including without limitation the rights
    * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    * copies of the Software, and to permit persons to whom the Software is
    * furnished to do so, subject to the following conditions:
    * 
    * The above copyright notice and this permission notice shall be included in all
    * copies or substantial portions of the Software.
    * 
    * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    * SOFTWARE. 
*/
/*
    * This file is main part of the PHPCodeSecurityAnalyzer package.
    * This library is free software; you can redistribute it and/or modify
    * it under the terms of the MIT license. Please read LICENSE for more details.
    * @package PHPCodeSecurityAnalyzer
    * @license MIT License
    * @link
    * @version 1.0.0
    * @Author: Rezwan ahmed sami
    *@Required: PHP 7.0 or greater and the php-parser library of nikic: https://github.com/nikic/PHP-Parser you can install it by `php composer.phar require nikic/php-parser`
*/
require $path.'vendor/autoload.php';

use PhpParser\Error;
use PhpParser\NodeDumper;
use PhpParser\ParserFactory;
use PhpParser\Node\Expr\FuncCall;

class PHPCodeSecurityAnalyzer {
    private $code;
    private $parser;
    private $traverser;
    
    function __construct($code) {
        $this->code = $code;
        $this->parser = (new ParserFactory)->create(ParserFactory::PREFER_PHP7);
        $this->traverser = new PhpParser\NodeTraverser;
    }

    public function AnalyzeSQLInjection(){
        try {
            $superglobalsMatches = [];
            $AddslashesArguments = [];
            $unsecuredVariables = [];
            $stmts = $this->parser->parse($this->code);

            $this->traverser->addVisitor(new class($superglobalsMatches, $AddslashesArguments) extends PhpParser\NodeVisitorAbstract {
                public $variablesInAddslashes = [];
                private $superglobalsMatches;
                private $AddslashesArguments;
                public function __construct(&$superglobalsMatches, &$AddslashesArguments) {
                    $this->superglobalsMatches = &$superglobalsMatches;
                    $this->AddslashesArguments = &$AddslashesArguments;
                }
    
                public function enterNode(PhpParser\Node $node) {
    
                    if ($node instanceof PhpParser\Node\Expr\Variable) {
                        if($node->name === '_GET' || $node->name === '_POST'){
                            $name = $node->name;
                            $startLine = $node->getAttribute('startLine');
                            $endLine = $node->getAttribute('endLine');
                            $VarArr = array("name" => $node->name, "startLine" => $startLine, "endLine" => $endLine);
                            $this->superglobalsMatches[] = $VarArr;
    
                        }
                    }
                    
    
                    if($node instanceof FuncCall && $node->name instanceof PhpParser\Node\Name) {
                        if($node->name->getLast() === 'addslashes' && count($node->args) === 1){
    
                            if ($node->args[0]->value->var instanceof PhpParser\Node\Expr\Variable) {
                                $argname = $node->args[0]->value->var->name;
                                $startLine = $node->args[0]->value->var->getAttribute('startLine');
                                $endLine = $node->args[0]->value->var->getAttribute('endLine');
                                $dim = $node->args[0]->value->dim->value;
                                $argArr = array("name" => $argname, "startLine" => $startLine, "endLine" => $endLine, "dim" => $dim);
                                $this->AddslashesArguments[] = $argArr;
                                
    
                            }
    
                        }
    
                    }
    
                }
            });

            $this->traverser->traverse($stmts);


            if (count($AddslashesArguments) < 1) {
                $unsecuredVariables = $AddslashesArguments;
            }

            if (count($superglobalsMatches) > 0) {


                // Search for each item in $superglobalsMatches within $AddslashesArguments
                foreach ($superglobalsMatches as $searchIndex => $searchItem) {
                    foreach ($AddslashesArguments as $dataIndex => $dataItem) {
                        if (
                            $dataItem['name'] === $searchItem['name'] &&
                            $dataItem['startLine'] === $searchItem['startLine'] &&
                            $dataItem['endLine'] === $searchItem['endLine']
                        ) {
                            // Unset the matching item from $superglobalsMatches
                            unset($superglobalsMatches[$searchIndex]);
                        }
                    }
                }

                // Reset the array keys after unsetting elements
                $unsecuredVariables = array_values($superglobalsMatches);
                // get the line number of the unsecured variables adn get the actual line code from the $code
                foreach ($unsecuredVariables as $key => $value) {
                    $line = $value['startLine'];
                    $unsecuredVariables[$key]['line'] = $line;
                    $unsecuredVariables[$key]['code'] = explode("\n", $this->code)[$line - 1];
                }

                // Output the updated $unsecuredVariables
                return $unsecuredVariables;
            }

            return [];

        } catch (Error $error) {
            throw new Exception("Error parsing code: ", $error->getMessage(), 1);
        }
        
                
    }
}

?>