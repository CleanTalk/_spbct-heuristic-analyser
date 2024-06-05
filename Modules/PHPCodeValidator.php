<?php

namespace CleantalkSP\Common\Scanner\HeuristicAnalyser\Modules;

class PHPCodeValidator
{
    /**
     * The result of checks
     *
     * @var array
     */
    public $check_list_result;

    /**
     * The tokens to be validated.
     *
     * @var Tokens
     */
    private $tokens;

    /**
     * PHPCodeValidator constructor.
     *
     * @param Tokens $tokens The tokens to be validated.
     */
    public function __construct($tokens)
    {
        $this->tokens = $tokens;
    }

    /**
     * Checks if the PHP code is valid.
     *
     * @return bool Returns true if the PHP code is valid, false otherwise.
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function isValidPHPCode()
    {
        return (
            $this->hasCorrectPHPOpenTags() &&
            $this->checkBraces() &&
            $this->checkQuotes() &&
            $this->checkDigitsStartedVariables()
        );
    }

    /**
     * Checks if the count of left and right braces and brackets are equal.
     *
     * @return bool Returns true if the count is equal, false otherwise.
     */
    private function checkBraces()
    {
        $braces_l_count = 0;
        $braces_r_count = 0;
        $brackets_l_count = 0;
        $brackets_r_count = 0;
        $parentheses_l_count = 0;
        $parentheses_r_count = 0;

        foreach ( $this->tokens as $token ) {
            if ( $token[0] === '__SERV' ) {
                if ( $token[1] === '(' ) {
                    $braces_l_count++;
                }
                if ( $token[1] === ')' ) {
                    $braces_r_count++;
                }
                if ( $token[1] === '[' ) {
                    $brackets_l_count++;
                }
                if ( $token[1] === ']' ) {
                    $brackets_r_count++;
                }
                if ( $token[1] === '{' ) {
                    $parentheses_l_count++;
                }
                if ( $token[1] === '}' ) {
                    $parentheses_r_count++;
                }
            }
        }

        if ( $braces_l_count !== $braces_r_count
            || $brackets_l_count !== $brackets_r_count
            || $parentheses_l_count !== $parentheses_r_count) {
            $this->check_list_result['checkBraces'] = 'Braces or brackets count is not equal';
            return false;
        }
        return true;
    }

    /**
     * Checks if the count of single and double quotes are even.
     *
     * @return bool Returns true if the count is even, false otherwise.
     */
    private function checkQuotes()
    {
        $double_quotes_count = 0;
        $single_quotes_count = 0;

        foreach ( $this->tokens as $token ) {
            if ( $token[0] === '__SERV' ) {
                if ( $token[1] === '"' ) {
                    $double_quotes_count++;
                }
                if ( $token[1] === "'" ) {
                    $single_quotes_count++;
                }
            }
        }

        if ( $double_quotes_count % 2 !== 0 || $single_quotes_count % 2 !== 0 ) {
            $this->check_list_result['checkQuotes'] = 'Quotes count is not even';
            return false;
        }
        return true;
    }

    /**
     * Checks if variables contain digits.
     *
     * @return bool Returns true if no variables contain digits, false otherwise.
     */
    private function checkDigitsStartedVariables()
    {
        foreach ( $this->tokens as $token ) {
            if ( $token[0] === 'T_VARIABLE' ) {
                if ( preg_match('/^\$\d.+/', $token[1]) ) {
                    $this->check_list_result['checkDigitsInVariables'] = 'Variable starts with digits [' . $token[1] . ']';
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Checks if the file does not contain PHP open tags ("<\?php" or `<\?`).
     *
     * @return bool Returns true if the file does not contain PHP open tags, false otherwise.
     */
    public function hasCorrectPHPOpenTags()
    {
        foreach ( $this->tokens as $_token => $content ) {
            if ( isset($content[0]) && isset($this->tokens->next1[0]) ) {
                if ( $content[0] === 'T_OPEN_TAG' ) {
                    //check if open tag is short
                    $is_short = isset($content[1]) && $content[1] === '<?';
                    if ( $is_short ) {
                        if ( $this->tokens->next1[0] !== 'T_WHITESPACE' ) {
                            $this->check_list_result['hasCorrectPHPOpenTags'] = 'PHP open tags are not valid';
                            return false;
                        }
                    } else {
                        return true;
                    }
                }
            }
        }

        return false;
    }
}
