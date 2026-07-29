<?php

namespace CleantalkSP\Common\Scanner\HeuristicAnalyser\Modules;

use CleantalkSP\Common\Scanner\HeuristicAnalyser\DataStructures\ExtendedSplFixedArray;
use CleantalkSP\Common\Scanner\HeuristicAnalyser\DataStructures\Token;

class Includes
{
    /**
     * @var array[] Contains arrays with array with each include tokens
     */
    public $includes = array();

    /**
     * @var Tokens
     */
    private $tokens;

    /**
     * @var Variables
     */
    private $variables_handler;

    /**
     * @var string Contains current directory with file we are working with
     */
    private $current_directory;

    /**
     * @var bool Show if we are analysing plain text, false if we are working with file
     */
    private $is_text;

    /**
     * @param Tokens $tokens_handler
     * @param Variables $variables_handler
     * @param $current_directory
     * @param $is_text
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function __construct(Tokens $tokens_handler, Variables $variables_handler, $current_directory, $is_text)
    {
        $this->tokens            = $tokens_handler;
        $this->variables_handler = $variables_handler;
        $this->current_directory = $current_directory;
        $this->is_text           = $is_text;
    }

    /**
     * Brings all such constructs to "include'path';" format
     *
     * @param ExtendedSplFixedArray $tokens
     * @param int $key
     *
     * @return bool
     * @psalm-suppress PossiblyUnusedMethod
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public function standardize($key)
    {
        if (
            $this->tokens->next1->value === '(' &&
            $this->tokens->current->isTypeOf('include')
        ) {
            $next_bracket_position = $this->tokens->searchForward($key, ')');

            if ( $next_bracket_position !== false ) {
                $this->tokens['next1'] = new Token(
                    'T_WHITESPACE',
                    ' ',
                    $this->tokens->next1->line,
                    $this->tokens->next1->key
                );
                $this->tokens->unsetTokens($next_bracket_position);

                return true;
            }
        }

        return false;
    }

    /**
     * Gets all of the include and require constructs. Checks for file extension and checks the path.
     *
     * @param int $key
     *
     * @return void
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function get($key)
    {
        if ( $this->tokens->current->isTypeOf('include') ) {
            // Get previous "file_exists" function
            $prev_file_exists__start = $this->tokens->searchBackward($key, 'file_exists');
            $prev_file_exists__end   = $prev_file_exists__start
                ? $this->tokens->searchForward($prev_file_exists__start, ')')
                : null;
            $file_exists             = $prev_file_exists__start && $prev_file_exists__end
                ? $this->tokens->getRange($prev_file_exists__start, $prev_file_exists__end)
                : null;

            // Get the include
            $include = $this->tokens->getRange(
                $key + 1,
                $this->tokens->searchForward($key, ';') - 1
            );

            if ( $include && count($include) ) {
                $this->process($include, $file_exists, $key);
            }
        }
    }

    /**
     * Processing given tokens with "includes".
     * Convert it to standard.
     *
     * @param $include
     * @param $file_exists
     * @param $key
     * @param $tokens
     *
     * @todo Create SpbctWP\Scanner\Heuristic\IncludeDTO
     *
     */
    public function process($include, $file_exists, $_key)
    {
        $include = $include->toArray();

        // Trim heading whitespace
        if ( $include[0]->type === 'T_WHITESPACE' ) {
            unset($include[0]);
            $include = array_values($include);
        }

        $properties = array(
            'include'     => $include,
            'dir'         => $this->current_directory, // Current directory
            'string'      => $this->tokens->current->line,         // String number in file
            'path'        => '',   // Absolute path to the file
            'is_absolute' => null, // Is path to file is absolute
            'name'        => '',   // Filename
            'error_free'  => true, // Checking for error ignoring "@" before include
            'not_url'     => true, // true = local path, false = remote URL
            'good'        => true, // Contains bad variables with user input
            'status'      => true, // Overall result. Good (true) by default
            'exists'      => true, // Is the file exists
            'ext'         => '',   // Extension of the file
            'ext_good'    => true, // Is extension is good (php|inc)
        );

        $properties['error_free'] = $this->tokens->prev1->value !== '@';
        $properties['good']       = ! $this->variables_handler->isSetOfTokensHasBadVariables($include);

        $path = $this->extractPathFromIncludeTokens($include);

        if ( $path !== null && $path !== '' ) {
            $this->fillPathProperties($properties, $path, $file_exists);
        }

        // Good = local include with a safe extension and without user-controlled variables.
        // Remote URLs must not get status=true (previously "! not_url" inverted this).
        $properties['status'] = $properties['good'] && $properties['not_url'] && $properties['ext_good'];

        // Adding include directive itself to the "include"
        array_unshift($properties['include'], $this->tokens->current);

        $this->includes[] = $properties;
    }

    /**
     * Extract filesystem path from include/require argument tokens.
     * Supports string literals and safe concatenations: ABSPATH . 'file', __DIR__ . '/file'.
     *
     * @param Token[] $include
     *
     * @return string|null Path without surrounding quotes, or null if unresolved
     */
    private function extractPathFromIncludeTokens(array $include)
    {
        // Strip wrapping parentheses: ( expr )
        if (
            count($include) >= 3 &&
            $include[0]->value === '(' &&
            $include[count($include) - 1]->value === ')'
        ) {
            $include = array_slice($include, 1, -1);
            $include = array_values($include);
        }

        // Drop whitespace tokens
        $include = array_values(array_filter($include, static function ($token) {
            return $token->type !== 'T_WHITESPACE';
        }));

        if ( ! count($include) ) {
            return null;
        }

        // Single string: include 'file.php';
        if ( count($include) === 1 && $include[0]->type === 'T_CONSTANT_ENCAPSED_STRING' ) {
            return $this->unquoteStringToken((string) $include[0]->value);
        }

        // Concatenation of safe parts: CONST/__DIR__/string . string . ...
        $parts = array();
        $expect_operand = true;
        foreach ( $include as $token ) {
            if ( $expect_operand ) {
                $part = $this->resolveConcatOperand($token);
                if ( $part === null ) {
                    return null;
                }
                $parts[] = $part;
                $expect_operand = false;
                continue;
            }

            if ( $token->value === '.' ) {
                $expect_operand = true;
                continue;
            }

            return null;
        }

        if ( $expect_operand || ! count($parts) ) {
            return null;
        }

        return implode('', $parts);
    }

    /**
     * @param Token $token
     *
     * @return string|null
     */
    private function resolveConcatOperand(Token $token)
    {
        if ( $token->type === 'T_CONSTANT_ENCAPSED_STRING' ) {
            return $this->unquoteStringToken((string) $token->value);
        }

        if ( $token->type === 'T_LNUMBER' || $token->type === 'T_DNUMBER' ) {
            return (string) $token->value;
        }

        // __DIR__
        if (
            $token->type === 'T_DIR' ||
            ($token->type === 'T_STRING' && $token->value === '__DIR__')
        ) {
            if ( $this->current_directory ) {
                return rtrim($this->current_directory, '/\\') . DIRECTORY_SEPARATOR;
            }

            return null;
        }

        // Known CMS constants (ABSPATH, WP_CONTENT_DIR, ...)
        if (
            $token->type === 'T_STRING' &&
            isset($this->variables_handler->constants[$token->value])
        ) {
            return (string) $this->variables_handler->constants[$token->value];
        }

        return null;
    }

    /**
     * @param string $token_value Quoted string token value
     *
     * @return string
     */
    private function unquoteStringToken($token_value)
    {
        $path = substr((string) $token_value, 1, -1);

        // Tokenized PHP source keeps escapes: 'C:\\dir\\file' → C:\\dir\\file (doubled).
        if ( preg_match('@^[A-Za-z]:\\\\@', $path) ) {
            $path = str_replace('\\\\', '\\', $path);
        }

        return $path;
    }

    /**
     * @param array $properties
     * @param string $path
     * @param mixed $file_exists
     *
     * @return void
     */
    private function fillPathProperties(array &$properties, $path, $file_exists)
    {
        $properties['path']    = $path;
        $properties['not_url'] = ! filter_var($properties['path'], FILTER_VALIDATE_URL);

        // Absolute: Unix /path, Windows C:\path or C:/path
        $properties['is_absolute'] = (bool) preg_match('@^([A-Za-z]:[\\\\/]|[\/])@', $properties['path']);

        // Make path absolute
        $properties['path'] = ! $properties['is_absolute'] && $properties['not_url']
            ? $this->current_directory . DIRECTORY_SEPARATOR . preg_replace(
                '@^([\\\\]|[\/])@',
                '',
                $properties['path']
            )
            : $properties['path'];

        // Prefer canonical filesystem path when the file exists
        $resolved_path = $properties['not_url'] ? realpath($properties['path']) : false;
        if ( $resolved_path ) {
            $properties['path'] = $resolved_path;
        }

        // Extract filename from the path
        $properties['name'] = basename($properties['path']);

        // Checks file for existence. null if checking text (not file).
        $properties['exists'] =
            $this->is_text &&
            ! (
                $file_exists &&
                $file_exists[2]->type === 'T_CONSTANT_ENCAPSED_STRING' &&
                $file_exists[2]->value === $properties['path']
            )
                ? null
                : (bool) $resolved_path;

        // Getting extension.
        $properties['ext'] = preg_match('/.*\.(\S{1,10})$/', $properties['path'], $matches) ? $matches[1] : '';

        // PHP executes included content regardless of extension (e.g. .js with PHP).
        $properties['ext_good'] = $properties['exists']
            || is_dir($properties['path'])
            || in_array($properties['ext'], array('php', 'inc'), true);
    }
}
