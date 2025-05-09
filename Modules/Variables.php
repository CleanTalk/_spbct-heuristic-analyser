<?php

namespace CleantalkSP\Common\Scanner\HeuristicAnalyser\Modules;

use CleantalkSP\Common\Scanner\HeuristicAnalyser\DataStructures\Token;
use CleantalkSP\Common\Scanner\HeuristicAnalyser\DataStructures\ExtendedSplFixedArray;

class Variables
{
    public $variables = array();
    public $variables_bad = array();
    public $arrays = array();
    public $constants = array();

    /**
     * @var Tokens
     */
    public $tokens;

    private $variables_types_to_concat = array(
        'T_CONSTANT_ENCAPSED_STRING',
        // 'T_ENCAPSED_AND_WHITESPACE',
        'T_LNUMBER',
        'T_DNUMBER',
    );

    private $sequences = array(

        'define_constant' => array(
            array('T_STRING', 'define'),
            array('__SERV', '(',),
            array('T_CONSTANT_ENCAPSED_STRING'),
            array('__SERV', ',',),
            array(array('T_CONSTANT_ENCAPSED_STRING', 'T_LNUMBER'))
        ),

        'array_equation_array' => array(
            array('__SERV', '=',),
            array('T_ARRAY'),
            array('__SERV', '(',),
        ),

        'array_equation_square_brackets' => array(
            array('__SERV', '=',),
            array('__SERV', '[',),
        )
    );

    public $variables_bad_default = array(
        '$_POST',
        '$_GET',
        '$_REQUEST',
        '$_COOKIE',
    );

    public function __construct(Tokens $tokens)
    {
        $this->tokens = $tokens;
    }

    /**
     * Replaces ${'string'} to $variable
     *
     * @param int $key
     *
     * @return bool Always returns false, because it doesn't unset current element
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public function convertVariableStrings($_key)
    {
        if (
            $this->tokens->current->value === '$' &&
            $this->tokens->next1->value === '{' &&
            $this->tokens->next2->type === 'T_CONSTANT_ENCAPSED_STRING'
        ) {
            $this->tokens['current'] = new Token(
                'T_VARIABLE',
                '$' . trim((string)$this->tokens->next2->value, '\'"'),
                $this->tokens->current->line,
                $this->tokens->current->key
            );
            $this->tokens->unsetTokens('next1', 'next2', 'next3');

            return true;
        }

        return false;
    }

    /**
     * Array equation via 'Array' word
     * $arr = array();
     *
     * @param int $key
     *
     * @return false Always returns false, because it doesn't unset any elements
     * @psalm-suppress UnusedVariable
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public function updateArrayEquation($key)
    {
        // Check the sequence for array equation
        if (
            $this->tokens->current->value !== '=' || // To speed up
            ! $this->tokens->checkSequence($this->sequences['array_equation_array'])
        ) {
            return false;
        }

        // Get end of array equation
        $variable_end = $this->tokens->searchForward($key, ';') - 1;
        if ( ! $variable_end ) {
            return false;
        }

        // Get all tokens of the array
        $array_tokens = $this->tokens->getRange($key + 4, $variable_end - 1);
        if ( ! $array_tokens ) {
            return false;
        }

        /** @ToDo so strange loop arguments */
        for (
            $i = 0;
            $arr_key = null, $arr_value = null, isset($array_tokens[$i]);
            $arr_key = null, $arr_value = null, $i++
        ) {
            // Case: [ 'a' => 'b' ] or [ 1 => 'b' ]
            if (
                isset($array_tokens[$i + 1]) && $array_tokens[$i + 1]->type === 'T_DOUBLE_ARROW' &&
                $array_tokens[$i]->isTypeOf('array_allowed_keys')
            ) {
                $arr_key   = trim($array_tokens[$i]->value, '\'"');
                $arr_value = $array_tokens[$i + 2];
                $i         += 2; // Skip

                // Case: [ 'a', 'b', 'c' ]
            } elseif ( $array_tokens[$i]->isTypeOf('array_allowed_values') ) {
                $arr_key   = isset($this->arrays[$this->tokens->current->value])
                    ? count($this->arrays[$this->tokens->current->value])
                    : 0;
                $arr_value = $array_tokens[$i];
            }

            if ( $arr_key && $arr_value ) {
                $array[$arr_key] = $arr_value;
            }
        }

        if ( isset($array) ) {
            $this->arrays[$this->tokens->current->value] = $array;
        }

        return false;
    }

    /**
     * Array equation via '[]' operator
     * $arr = [];
     *
     * @param int $key
     *
     * @return false returns false if current token( $tokens[ $key ] ) was unset or true if isn't
     * @psalm-suppress UnusedVariable
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public function updateArrayEquationShort($key)
    {
        if (
            $this->tokens->current->value !== '=' || // To speed up
            ! $this->tokens->checkSequence($this->sequences['array_equation_square_brackets'])
        ) {
            return false;
        }

        $variable_end = $this->tokens->searchForward($key, ';') - 1;
        if ( ! $variable_end ) {
            return false;
        }

        // Get all tokens of the array
        $array_tokens = $this->tokens->getRange($key + 3, $variable_end - 1);
        if ( ! $array_tokens ) {
            return false;
        }

        /** @ToDo so strange loop arguments */
        for (
            $i = 0;
            $arr_key = null, $arr_value = null, isset($array_tokens[$i]);
            $arr_key = null, $arr_value = null, $i++
        ) {
            // Case: [ 'a' => 'b' ] or [ 1 => 'b' ]
            if (
                isset($array_tokens[$i + 1]) && $array_tokens[$i + 1]->type === 'T_DOUBLE_ARROW' &&
                $array_tokens[$i]->isTypeOf('array_allowed_keys')
            ) {
                $arr_key   = trim($array_tokens[$i]->value, '\'"');
                $arr_value = $array_tokens[$i + 2];
                $i         += 2; // Skip

                // Case: [ 'a', 'b', 'c' ]
            } elseif ( $array_tokens[$i]->isTypeOf('array_allowed_values') ) {
                $arr_key   = isset($this->arrays[$this->tokens->current->value])
                    ? count($this->arrays[$this->tokens->current->value])
                    : 0;
                $arr_value = $array_tokens[$i];
            }

            if ( $arr_key && $arr_value ) {
                $array[$arr_key] = $arr_value;
            }
        }

        if ( isset($array) ) {
            $this->arrays[$this->tokens->current->value] = $array;
        }

        return false;
    }

    /**
     * Array. New element equation via
     * $arr[] = 'value';
     *
     * @param int $key
     *
     * @return false returns false if current token( $tokens[ $key ] ) was unset or true if isn't
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public function updateArrayNewElement($key)
    {
        if (
            $this->tokens->next1->value === '[' &&
            $this->tokens->next2->value === ']' &&
            $this->tokens->next3->value === '='
        ) {
            $var_temp = $this->tokens->getRange(
                $key + 4,
                $this->tokens->searchForward($key, ';') - 1
            );

            if ( $var_temp !== false && count($var_temp) ) {
                $var_temp = $var_temp[0];
                if ( $var_temp->isTypeOf('array_allowed_values') ) {
                    $this->arrays[$this->tokens->current->value][] = array(
                        $var_temp[0],
                        $var_temp[1],
                        $var_temp[2],
                    );
                }
            }
        }

        return false;
    }

    /**
     * Simple equation
     * $a = 'value';
     *
     * @param int $key
     *
     * @return false returns false if current token( $tokens[ $key ] ) was unset or true if isn't
     * @psalm-suppress NullPropertyFetch
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public function updateVariablesEquation($key)
    {
        // Simple equation
        // $a = 'value';
        if (
            $this->tokens->current->type === 'T_VARIABLE' &&
            $this->tokens->next1->value === '='
        ) {
            $variable_start = $this->tokens->searchForward($key, '=') + 1;
            $variable_end = $this->tokens->searchForward($key, ';') - 1;
            if ( $variable_end ) {
                $variable_tokens = $this->tokens->getRange($variable_start, $variable_end);

                if (
                    count($variable_tokens) === 3 &&
                    $variable_tokens[0]->value === '"' &&
                    $variable_tokens[1]->type === 'T_ENCAPSED_AND_WHITESPACE' &&
                    $variable_tokens[2]->value === '"'
                ) {
                    $variable_tokens = array(
                        new Token(
                            'T_CONSTANT_ENCAPSED_STRING',
                            '\'' . $variable_tokens[1]->value . '\'',
                            $variable_tokens[1]->line,
                            $variable_tokens[1]->key
                        )
                    );
                }
                // If the variable exists
                if (
                    isset($this->variables[$this->tokens->current->value]) &&
                    is_object($this->variables[$this->tokens->current->value]) &&
                    $this->variables[$this->tokens->current->value] instanceof ExtendedSplFixedArray
                ) {
                    $this->variables[$this->tokens->current->value]->append($variable_tokens);
                } else {
                    $this->variables[$this->tokens->current->value] = $variable_tokens;
                }
            }
        }

        return false;
    }

    /**
     * Equation with concatenation. $a .= 'value';
     * Adding right expression to the appropriate variable
     *
     * @param int $key
     *
     * @return false always return false
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public function updateVariablesEquationWithConcatenation($key)
    {
        if (
            $this->tokens->current->type === 'T_VARIABLE' &&
            $this->tokens->next1->type === 'T_CONCAT_EQUAL'
        ) {
            $tokens_of_variable = $this->tokens->getRange(
                $key + 2,
                $this->tokens->searchForward($key, ';') - 1
            );

            if ( $tokens_of_variable ) {
                // Variable in a double quotes like $a .= "$b";
                // We don't touch variables in a single quotes like $a .= 'value';
                if (
                    count($tokens_of_variable) === 3 &&
                    $tokens_of_variable[0]->value === '"' &&
                    $tokens_of_variable[1]->type === 'T_ENCAPSED_AND_WHITESPACE' &&
                    $tokens_of_variable[2]->value === '"'
                ) {
                    $tokens_of_variable = array(
                        new Token(
                            'T_CONSTANT_ENCAPSED_STRING',
                            '\'' . $tokens_of_variable[1]->value . '\'',
                            $tokens_of_variable[1]->line,
                            $tokens_of_variable[1]->key
                        ),
                    );
                }

                // If the variable exists
                if (
                    isset($this->variables[$this->tokens->current->value]) &&
                    is_object($this->variables[$this->tokens->current->value]) &&
                    $this->variables[$this->tokens->current->value] instanceof ExtendedSplFixedArray
                ) {
                    $this->variables[$this->tokens->current->value]->append($tokens_of_variable);
                } else {
                    $this->variables[$this->tokens->current->value] = $tokens_of_variable;
                }
            }
        }

        return false;
    }

    /**
     * Equation by unnecessary substr function
     * $a = substr($string, 0);
     *
     * substr($string, 0) is equivalent to $string
     *
     * @param int $key
     *
     * @return false returns false if fake substr construct not found
     * @psalm-suppress NullPropertyFetch
     * @psalm-suppress TypeDoesNotContainType
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public function updateVariablesEquationByFakeSubstr($key)
    {
        if (
            $this->tokens->current->type === 'T_VARIABLE' &&
            $this->tokens->next1->value === '='
        ) {
            $variable_start = $this->tokens->searchForward($key, '=') + 1;
            $variable_end = $this->tokens->searchForward($key, ';') - 1;
            if ( $variable_end ) {
                $variable_tokens = $this->tokens->getRange($variable_start, $variable_end);

                if (
                    count($variable_tokens) === 6 &&
                    $variable_tokens[0]->value === 'substr' &&
                    $variable_tokens[1]->value === '(' &&
                    $variable_tokens[2]->type === 'T_VARIABLE' &&
                    $variable_tokens[3]->value === ',' &&
                    ($variable_tokens[4]->type === 'T_LNUMBER' && $variable_tokens[4]->value === '0') &&
                    $variable_tokens[5]->value === ')' &&
                    isset($this->variables[$variable_tokens[2]->value])
                ) {
                    $variable_token = $this->variables[$variable_tokens[2]->value];
                    $replace_variable_token = array(
                        new Token(
                            'T_CONSTANT_ENCAPSED_STRING',
                            '\'' . trim($variable_token[0]->value, '"\'') . '\'',
                            $variable_tokens[1]->line,
                            $variable_tokens[1]->key
                        )
                    );

                    $this->variables[$this->tokens->current->value] = $replace_variable_token;
                }
            }
        }
        return false;
    }

    /**
     * Search and remember constants definition
     * define('CONSTANT_NAME','CONSTANT_VALUE'
     *
     * @param int $key
     *
     * @return false returns false if current token( $tokens[ $key ] ) was unset or true if isn't
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public function updateConstants($_key)
    {
        if (
            $this->tokens->current->value === 'define' &&
            $this->tokens->checkSequence($this->sequences['define_constant'])
        ) {
            $constant_name                   = trim((string)$this->tokens->next2->value, '\'"');
            $this->constants[$constant_name] = trim((string)$this->tokens->next4->value, '\'"');
        }

        return false;
    }

    /**
     * Concatenate variable in $this->variables
     *
     * @return void
     */
    public function concatenate()
    {
        foreach ( $this->variables as &$var ) {
            for (
                $key = 0, $key_max = count($var);
                $key < $key_max;
                $key++
            ) {
                $current = isset($var[$key]) ? $var[$key] : null;
                $next = isset($var[$key + 1]) ? $var[$key + 1] : null;
                if (
                    ($current && in_array($current->type, $this->variables_types_to_concat, true)) &&
                    ($next && in_array($next->type, $this->variables_types_to_concat, true))
                ) {
                    $var[$key] = new Token(
                        $current->type,
                        "'" . trim($current->value, '\'"') . trim($next->value, '\'"') . "'",
                        $current->line,
                        $current->key
                    );
                    unset($var[$key + 1]);
                    $var->reindex($key); // Reindex start form given key
                }
            }
        }
    }

    public function concatenateVars($_key)
    {
        if (
            $this->tokens->current->type === 'T_VARIABLE' &&
            $this->tokens->next1->type === 'T_CONCAT_EQUAL' &&
            $this->tokens->next2->type === 'T_CONSTANT_ENCAPSED_STRING'
        ) {
            $var_first_declaration = $this->tokens->searchForward(0, $this->tokens->current[1]); // 10

            if ( ! $var_first_declaration ) {
                return false;
            }

            $var_expression = $this->tokens->getRange(
                $this->tokens[$var_first_declaration][3],
                $this->tokens->searchForward($this->tokens[$var_first_declaration][3], ';') - 1
            );

            if ( ! count($var_expression) ) {
                return false;
            }

            $tokens_of_variable_for_concat = $this->tokens->getRange(
                $this->tokens->current[3] + 3,
                $this->tokens->searchForward($this->tokens->current[3], ';') - 1
            );

            foreach ( $tokens_of_variable_for_concat as $token ) {
                if ($token->type === 'T_CONSTANT_ENCAPSED_STRING') {
                    $last_txt_token = $var_expression[count($var_expression) - 1][1];
                    $var_expression[count($var_expression) - 1][1] = implode('', [
                        mb_substr($last_txt_token, 0, -1),
                        trim((string)$token[1], '\'\"'),
                        mb_substr($last_txt_token, -1)
                    ]);
                }
            }

            $this->tokens->unsetExpression('current');

            return true;
        }

        return false;
    }

    /**
     * Replaces the current variable token with its value if it's a simple variable or a function call.
     * This function searches for the first declaration of the variable and replaces the current token
     * with the value found in that declaration.
     *
     * @param int $_key The key of the current token in the token array.
     * @return void
     */
    public function replaceVars($_key)
    {
        if ( $this->tokens->current->type === 'T_VARIABLE' ) {
            if ( $this->tokens->next1->value === '(' ) {
                $var_first_declaration = $this->tokens->searchForward(0, (string)$this->tokens->current->value); // 10

                if ( ! $var_first_declaration ) {
                    return;
                }

                $var_expression = $this->tokens->getRange(
                    $this->tokens[$var_first_declaration][3],
                    $this->tokens->searchForward($this->tokens[$var_first_declaration][3], ';') - 1
                );

                if ( isset($var_expression[2]) && isset($var_expression[2][1]) ) {
                    $this->tokens->current->value = trim($var_expression[2][1], '\'\"');
                }
            }
        }
    }

    /**
     * Replaces the current array variable token with its specific element value.
     * This function checks if the next token is an array access and then replaces the current token
     * with the value of the specified array element.
     *
     * @param int $_key The key of the current token in the token array.
     * @return void
     */
    public function replaceArrayVars($_key)
    {

        if ( $this->tokens->current->type === 'T_VARIABLE' ) {
            if ( $this->tokens->next1->value === '[' && $this->tokens->next2->type === 'T_LNUMBER') {
                $var_first_declaration = $this->tokens->searchForward(0, (string)$this->tokens->current->value); // 10

                if ( ! $var_first_declaration ) {
                    return;
                }

                $var_expression = $this->tokens->getRange(
                    $this->tokens[$var_first_declaration][3],
                    $this->tokens->searchForward($this->tokens[$var_first_declaration][3], ';') - 1
                );

                if (
                    !isset($this->tokens->next2->value) ||
                    !is_numeric($this->tokens->next2->value) ||
                    ! isset($var_expression[2][1][$this->tokens->next2->value + 1])
                ) {
                    return;
                }

                $this->tokens['current'] = new Token(
                    'T_CONSTANT_ENCAPSED_STRING',
                    '\'' . trim($var_expression[2][1][$this->tokens->next2->value + 1], '\'\"') . '\'',
                    $this->tokens->current->line,
                    $this->tokens->current->key
                );

                $this->tokens->unsetTokens('next1', 'next2', 'next3');
            }
        }
    }

    /**
     * Replace variables with its content
     *
     * @param $_key
     *
     * @return void
     */
    public function replace($_key)
    {
        // Replace variable
        if ( $this->tokens->current->type === 'T_VARIABLE' ) {
            $variable_name = $this->tokens->current->value;

            // Arrays
            if ( $this->isTokenInArrays($this->tokens->current) ) {
                // Array element
                if (
                    $this->tokens->next1->value === '[' &&
                    $this->tokens->next1->type === 'T_LNUMBER' &&
                    $this->tokens->next3->isValueIn(['.', '(', ';'])
                ) {
                    if ( isset($this->arrays[$variable_name][$this->tokens->next1->value][1]) ) {
                        if ( $this->tokens->next3->value === '(' ) {
                            $this->tokens['current'] = new Token(
                                'T_STRING',
                                substr($this->arrays[$variable_name][$this->tokens->next1->value][1], 1, -1),
                                $this->tokens->current->line,
                                $this->tokens->current->key
                            );
                        } elseif ( $this->tokens->next3->value === '.' ) {
                            $this->tokens['current'] = new Token(
                                'T_CONSTANT_ENCAPSED_STRING',
                                '\'' . $this->arrays[$variable_name][$this->tokens->next1->value][1] . '\'',
                                $this->tokens->current->line,
                                $this->tokens->current->key
                            );
                        } else {
                            $this->tokens['current'] = new Token(
                                $this->arrays[$variable_name][$this->tokens->next1->type][0],
                                '\'' . $this->arrays[$variable_name][$this->tokens->next1->value][1] . '\'',
                                $this->tokens->current->line,
                                $this->tokens->current->key
                            );
                        }

                        $this->tokens->unsetTokens('next1', 'next2', 'next3');

                        return;
                    }
                }
                // Variables
            } elseif (
                $this->isTokenInVariables($this->tokens->current) &&
                count($this->variables[$variable_name]) === 1 &&
                in_array($this->variables[$variable_name][0][0], $this->variables_types_to_concat, true)
            ) {
                // Array or symbol from string replacement
                if (
                    $this->tokens->next2->type === 'T_LNUMBER' &&
                    $this->tokens->next1->isValueIn(['[', '{'])
                ) {
                    if ( isset(
                        $this->variables[$variable_name][0][1][$this->tokens->next2->value],
                        $this->variables[$variable_name][0][1][$this->tokens->next2->value + 1]
                    ) ) {
                        $this->tokens['current'] = new Token(
                            'T_CONSTANT_ENCAPSED_STRING',
                            '\'' . $this->variables[$variable_name][0][1][$this->tokens->next2->value + 1] . '\'',
                            $this->tokens->current->line,
                            $this->tokens->current->key
                        );
                        $this->tokens->unsetTokens('next1', 'next2', 'next3');

                        return;
                    }

                    // @todo Learn to replace $$var to $var_value
                    // }elseif( is_array( $next ) && $next === 'T_VARIABLE' ){

                    // Single variable replacement
                } else {
                    // Variables function
                    if ( $this->tokens->next1->value === '(' ) {
                        $this->tokens['current'] = new Token(
                            'T_STRING',
                            substr($this->variables[$variable_name][0][1], 1, -1),
                            $this->tokens->current->line,
                            $this->tokens->current->key
                        );
                        // Variables in double/single quotes
                    } elseif ( ! $this->tokens->next1->isTypeOf('equation') && $this->tokens->next1->value !== '=' ) {
                        // If the variable is within quotes
                        if (
                            $this->tokens->prev1->value === '"' ||
                            $this->tokens->prev1->value === '\''
                        ) {
                            $this->tokens['current'] = new Token(
                                ! $this->tokens->prev1->value === '"' ? 'T_CONSTANT_ENCAPSED_STRING' : 'T_ENCAPSED_AND_WHITESPACE',
                                ! $this->tokens->prev1->value === '"' ? $this->variables[$variable_name][0][1] : substr(
                                    $this->variables[$variable_name][0][1],
                                    1,
                                    -1
                                ),
                                $this->tokens->current->line,
                                $this->tokens->current->key
                            );
                            // If the variable is without quotes, like integers
                        } else {
                            $this->tokens['current'] = new Token(
                                $this->variables[$variable_name][0][0],
                                $this->variables[$variable_name][0][1],
                                $this->tokens->current->line,
                                $this->tokens->current->key
                            );
                        }
                    }
                }
            }

            // Constant replacement
            // @todo except cases when name of constant equal to something. Check type and siblings tokens
        } elseif ( $this->isTokenInConstants($this->tokens->current) ) {
            $this->tokens['current'] = new Token(
                'T_CONSTANT_ENCAPSED_STRING',
                '\'' . $this->constants[$this->tokens->current->value] . '\'',
                $this->tokens->current->line,
                $this->tokens->current->key
            );
        }
    }

    /**
     * Add variables to bad list depends on:
     *  - containing user input ($_POST,$_GET,...)
     *  - containing variables contain user input
     *
     * See $this->variables_bad to view the list of user input variables
     *
     * @return void
     */
    public function detectBad()
    {
        // Perform until count of bad variables becomes stable
        do {
            // Count bad variables on start of each iteration
            $bad_vars_count = count($this->variables_bad);

            foreach ( $this->variables as $name => $variable_tokens ) {
                if ( $this->isSetOfTokensHasBadVariables($variable_tokens) ) {
                    $this->variables_bad[$name] = $variable_tokens;
                }
            }
        } while ( $bad_vars_count !== count($this->variables_bad) );
    }

    /**
     * Check the set of tokens for bad variables
     *
     * @param Token[]|ExtendedSplFixedArray $tokens Set of tokens
     *
     * @return bool
     */
    public function isSetOfTokensHasBadVariables($tokens, $skip_sanitized = false)
    {
        $counter = 0;
        foreach ( $tokens as $token ) {
            $counter++;
            if (
                $token->type === 'T_VARIABLE' &&
                (
                    in_array($token->value, $this->variables_bad_default, true) ||
                    in_array($token->value, $this->variables_bad, true)
                )
            ) {
                if ($skip_sanitized) {
                    $sanitizing_function_names = array(
                        'sanitize_text_field',
                        'prepare',
                    );
                    $has_sanitization = $this->tokens->searchBackward($token->key, $sanitizing_function_names, $counter);
                    $is_short_shape = $this->tokens->searchForward($token->key, '?', 10);
                    if ($has_sanitization || $is_short_shape) {
                        continue;
                    }
                }
                return true;
            }
        }

        return false;
    }

    /**
     * Check if the given token in arrays
     *
     * @param $token
     *
     * @return bool
     */
    public function isTokenInArrays($token)
    {
        return $token->type === 'T_VARIABLE' && isset($this->arrays[$token->value]);
    }

    /**
     * Check if the given token in variables
     *
     * @param $token
     *
     * @return bool
     */
    public function isTokenInVariables($token)
    {
        return $token->type === 'T_VARIABLE' && isset($this->variables[$token->value]);
    }

    /**
     * Check if the given token in constants
     *
     * @param $token
     *
     * @return bool
     */
    public function isTokenInConstants($token)
    {
        return $token->type === 'T_STRING' && isset($this->constants[$token->value]);
    }
}
