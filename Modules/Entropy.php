<?php

namespace CleantalkSP\Common\Scanner\HeuristicAnalyser\Modules;

use CleantalkSP\Common\Scanner\HeuristicAnalyser\Vendors\TiktokenPhp\src\Encoder;

class Entropy
{
    /**
     * Min length of variable to be suspicious
     */
    const SUSPICIOUS_VARIABLES_MIN_LENGTH = 3;
    /**
     * Threshold for variable tokenization, less is suspicious
     */
    const SUSPICIOUS_VARIABLES_THRESHOLD = 2;
    /**
     * Min length of array key to be suspicious
     */
    const SUSPICIOUS_ARRAY_KEYS_ENTROPY__MIN_KEY_LENGTH = 3;
    /**
     * Threshold for array keys tokenization, less is suspicious. Increment this to force sensitivity.
     */
    const SUSPICIOUS_ARRAY_KEYS_ENTROPY__THRESHOLD = 2.5;
    /**
     * How to reduce a single array key tokenization before check to show in the verdict. Increment this to force sensitivity.
     */
    const SUSPICIOUS_ARRAY_KEYS_ENTROPY__VERDICT_SHOWN_MULTIPLIER = 0.5;
    /**
     *  MIn length of int key to be suspicious
     */
    const SUSPICIOUS_ARRAY_KEYS_LONGINT__MIN_KEY_LENGTH = 4;
    /**
     * Threshold for long int keys in array, more is suspicious
     */
    const SUSPICIOUS_ARRAY_KEYS_LONGINT__THRESHOLD = 0.3;

    const SUSPICIOUS_ARRAY_KEYS_LONGINT_MIN__COUNT_OF_SUSPICIOUS = 5;

    /**
     * Verdict name of long integer in array key
     */
    const ENTROPY_VERDICT_ARRAY_KEYS_LONGINT_NAME = 'Long integer in array key';
    /**
     * Verdict name of high entropy in array key
     */
    const ENTROPY_VERDICT_ARRAY_KEYS_HIGH_ENTROPY_NAME = 'High entropy in array key';
    /**
     * Verdict name of high entropy in variable
     */
    const ENTROPY_VERDICT_VARIABLES_HIGH_ENTROPY_NAME = 'High entropy in variable name';
    /**
     * @var array|null
     */
    private $entropy_verdict;

    /**
     * Flag - is need to check variables separately
     * @var bool
     */
    private $is_file_suspicious;
    /**
     * @var bool
     */
    private $has_suspicious_variables;
    /**
     * @var array
     */
    private $suspicious_array_calls = array();

    /**
     * Path to the file
     * @var string
     */
    private $path_to_file;

    /**
     * Filtered content with no comments, whitespaces. Used to find suspicious array keys.
     * @var string
     */
    private $filtered_content;

    /**
     * @param string $path_to_file
     * @param Tokens $tokens
     */
    public function __construct($path_to_file, $tokens)
    {
        $this->path_to_file = $path_to_file;
        // do filter content
        $simplifier = new Simplifier($tokens);
        foreach ($tokens as $token) {
            $simplifier->deleteNonCodeTokens($token);
            $simplifier->stripWhitespaces($token);
        }
        $this->filtered_content = $tokens->glueAllTokens();
        //process
        $this->is_file_suspicious = $this->analyseFile();
    }

    /**
     * Analysing variables one by one and making verdict to each ones
     *
     * @param Variables $variables
     * @return void
     */
    public function extractSuspiciousVariables($variables)
    {
        if ( !$this->is_file_suspicious ) {
            return;
        }

        $encoder = new Encoder();

        if ( $this->has_suspicious_variables ) {
            $variables_obj = $variables->variables;
            $variable_names = array_keys($variables->variables);

            if ( !count($variable_names) ) {
                return;
            }

            $detected_unreadable_variables = array();
            foreach ( $variable_names as $variable ) {
                // do not change empty state! this change is from heur package!
                if ( empty($variables_obj[$variable]) ) {
                    continue;
                }
                if ( strpos($variable, '_') === 0 || strlen($variable) < 5 ) {
                    continue;
                }
                $num_tokens = count($encoder->encode($variable));
                if ( ! $num_tokens ) {
                    continue;
                }
                $res = strlen($variable) / $num_tokens;
                $line_number_met_on = isset($variables_obj[$variable][0][2]) && is_scalar($variables_obj[$variable][0][2])
                    ? (int)$variables_obj[$variable][0][2]
                    : null;
                if ( $res < static::SUSPICIOUS_VARIABLES_THRESHOLD && null !== $line_number_met_on ) {
                    $detected_unreadable_variables[$line_number_met_on] = array(static::ENTROPY_VERDICT_VARIABLES_HIGH_ENTROPY_NAME);
                }
            }

            if ( count($detected_unreadable_variables) ) {
                $this->entropy_verdict = $detected_unreadable_variables;
            }
        }

        if ( empty($this->entropy_verdict) && !empty($this->suspicious_array_calls)) {
            $this->entropy_verdict = $this->suspicious_array_calls;
        }
    }

    /**
     * Analysing average unreadable score for the full file
     *
     * @return bool
     */
    private function analyseFile()
    {
        $this->has_suspicious_variables = $this->analyseVariableCalls();
        if ( !$this->has_suspicious_variables ) {
            $this->suspicious_array_calls = $this->analyseArrayKeyCalls();
        }
        return $this->has_suspicious_variables || !empty($this->suspicious_array_calls);
    }

    /**
     * Analysing average unreadable variable score for the full file
     *
     *
     * @return bool
     */
    private function analyseVariableCalls()
    {
        $variable_names = $this->extractVariableNames();

        $filtered_names = array();

        foreach ( $variable_names as $variable_name ) {
            if ( strpos($variable_name, '_') !== 0 && strlen($variable_name) >= static::SUSPICIOUS_VARIABLES_MIN_LENGTH ) {
                $filtered_names[] = $variable_name;
            }
        }

        $filtered_names = array_unique($filtered_names);
        if ( count($filtered_names) > static::SUSPICIOUS_VARIABLES_MIN_LENGTH ) {
            $encoder = new Encoder();
            $sum = 0;

            foreach ( $filtered_names as $filtered_name ) {
                $num_tokens = count($encoder->encode($filtered_name));
                if ( ! $num_tokens ) {
                    continue;
                }
                $res = strlen($filtered_name) / $num_tokens;
                $sum += $res;
            }

            $average_tokenization = $sum / count($filtered_names);

            if ( $average_tokenization < static::SUSPICIOUS_VARIABLES_THRESHOLD ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Analysing average unreadable variable score for the full file
     *
     * @return array
     */
    private function analyseArrayKeyCalls()
    {
        //perform entropy analysis for array keys
        $suspicious_calls = $this->analyzeArrayKeysEntropy();

        if (empty($suspicious_calls)) {
            //if nothing found perform long int count analysis
            $suspicious_calls = $this->analyzeArrayKeysLongInt();
        }

        return $suspicious_calls;
    }

    /**
     * Analysing average unreadable array keys score for the full file
     *
     * @return array
     */
    private function analyzeArrayKeysEntropy()
    {
        $output = array();
        $array_keys_calls = $this->extractArrayKeysWordLike();
        $filtered_keys = array();

        foreach ( $array_keys_calls as $key ) {
            if ( strlen($key) >= static::SUSPICIOUS_ARRAY_KEYS_ENTROPY__MIN_KEY_LENGTH ) {
                $filtered_keys[] = $key;
            }
        }

        $filtered_keys = array_unique($filtered_keys);
        if ( count($filtered_keys) > 3 ) {
            $encoder = new Encoder();
            $sum = 0;

            foreach ( $filtered_keys as $key ) {
                $num_tokens = count($encoder->encode($key));
                if ( ! $num_tokens ) {
                    continue;
                }
                $res = strlen($key) / $num_tokens;
                $sum += $res;
            }

            $average_array_key_tokenization = $sum / count($filtered_keys);
            if ( (float)$average_array_key_tokenization < static::SUSPICIOUS_ARRAY_KEYS_ENTROPY__THRESHOLD ) {
                foreach ( $filtered_keys as $key ) {
                    $num_tokens = count($encoder->encode($key));
                    if ( ! $num_tokens ) {
                        continue;
                    }
                    $res = strlen($key) / $num_tokens;
                    if ( (float)$res < static::SUSPICIOUS_ARRAY_KEYS_ENTROPY__THRESHOLD * static::SUSPICIOUS_ARRAY_KEYS_ENTROPY__VERDICT_SHOWN_MULTIPLIER ) {
                        $found_on_lines = static::findRowsNumWithPattern($this->path_to_file, '/\[\'' . $key . '\'\]/');
                        foreach ( $found_on_lines as $line_num ) {
                            $output[$line_num] = array(static::ENTROPY_VERDICT_ARRAY_KEYS_HIGH_ENTROPY_NAME);
                        }
                    }
                }
            }
        }
        return $output;
    }

    /**
     * Analysing average long int in array call score for the full file
     *
     * @return array
     */
    private function analyzeArrayKeysLongInt()
    {
        $output = array();
        $array_keys_int = $this->extractArrayKeysIntLike();
        $total_int_keys_calls = count($array_keys_int);
        $probably_long_int = array();
        foreach ($array_keys_int as $int) {
            if (strlen($int) >= static::SUSPICIOUS_ARRAY_KEYS_LONGINT__MIN_KEY_LENGTH) {
                $found_on_lines = static::findRowsNumWithPattern($this->path_to_file, '/\[' . $int . '\]/');
                foreach ($found_on_lines as $line_num) {
                    $probably_long_int[$line_num] = array(static::ENTROPY_VERDICT_ARRAY_KEYS_LONGINT_NAME);
                }
            }
        }
        if (
            count($probably_long_int) >= static::SUSPICIOUS_ARRAY_KEYS_LONGINT_MIN__COUNT_OF_SUSPICIOUS &&
            (float)($total_int_keys_calls / count($probably_long_int)) > static::SUSPICIOUS_ARRAY_KEYS_LONGINT__THRESHOLD
        ) {
            $output = $probably_long_int;
        }
        return $output;
    }

    /**
     * Extract variable names from the file
     * @return string[]
     */
    private function extractVariableNames()
    {
        $pattern = '/\$([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)/';
        return static::extractContentByRegexp($this->filtered_content, $pattern);
    }

    /**
     * Extract int-like array keys from the file
     * @return string[]
     */
    private function extractArrayKeysWordLike()
    {
        $pattern = '/\[\'([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)\'\]/';
        return static::extractContentByRegexp($this->filtered_content, $pattern);
    }

    /**
     * Extract word-like array keys from the file
     * @return string[]
     */
    private function extractArrayKeysIntLike()
    {
        $pattern = '/\[(\d+)]/';
        return static::extractContentByRegexp($this->filtered_content, $pattern);
    }

    /**
     * @param string $content
     * @param $pattern
     *
     * @return array|string[]
     */
    private static function extractContentByRegexp($content, $pattern)
    {
        preg_match_all($pattern, $content, $matches);
        return isset($matches[1]) ? $matches[1] : array();
    }

    /**
     * Find each row in a file that matches a specified regular expression.
     *
     * @param string $filePath The path to the file.
     * @param string $pattern The regular expression pattern to search for.
     * @return array An array of lines that match the regular expression.
     */
    private static function findRowsNumWithPattern($filePath, $pattern)
    {
        $result = array();
        if (!class_exists('\SplFileObject')) {
            return array();
        }
        $file = new \SplFileObject($filePath);
        $line_num = 0;

        while (!$file->eof()) {
            $line_num++;
            $line = $file->fgets();
            if (preg_match($pattern, $line)) {
                $result[] = $line_num;
            }
        }

        return $result;
    }

    /**
     * @return array|null
     */
    public function getEntropyVerdict($max_keys_number = 0)
    {
        if (
            $max_keys_number !== 0
            && is_array($this->entropy_verdict)
            && count($this->entropy_verdict) > $max_keys_number
        ) {
            return static::reduceVerdict($this->entropy_verdict, $max_keys_number);
        }
        return $this->entropy_verdict;
    }

    /**
     * Reduce verdict to max keys number
     * @param $verdict
     * @param $max_keys
     *
     * @return array
     */
    private static function reduceVerdict($verdict, $max_keys)
    {
        $verdict_of_array_checks = array();
        $verdict_other = array();
        // we need to separate array checks from other checks
        foreach ($verdict as $line => $value) {
            if (is_array($value)) {
                if (
                    $value[0] === static::ENTROPY_VERDICT_ARRAY_KEYS_HIGH_ENTROPY_NAME ||
                    $value[0] === static::ENTROPY_VERDICT_ARRAY_KEYS_LONGINT_NAME
                ) {
                    $verdict_of_array_checks[$line] = $value;
                } else {
                    $verdict_other[$line] = $value;
                }
            }
        }
        if (count($verdict_other) + count($verdict_of_array_checks) !== count($verdict)) {
            throw new \RuntimeException('Verdict reduction error');
        }
        //first, if we have found array checks - reduce them
        if (count($verdict_of_array_checks) > 2 && count($verdict_other) <= $max_keys) {
            $verdict_of_array_checks = static::halfVerdictArray($verdict_of_array_checks, $max_keys - count($verdict_other));
            return count($verdict_other) // if other checks found - merge them
                ? array_merge($verdict_other, $verdict_of_array_checks)
                : $verdict_of_array_checks;
        }
        //if we have no array checks - reduce other checks by limit
        return array_slice($verdict, 0, $max_keys, true);
    }

    /**
     * Reduce verdict to max keys number deleting every second key.
     * @param $array
     * @param $max_keys
     *
     * @return array
     */
    private static function halfVerdictArray($array, $max_keys)
    {
        $counter = 3; //save first elem always
        $halfed = array();
        foreach ($array as $index => $value) {
            $counter++;
            if ($counter % 2 == 1) {
                $halfed[$index] = $value;
            }
        }
        unset($array);
        return count($halfed) > $max_keys
            ? static::halfVerdictArray($halfed, $max_keys)
            : $halfed;
    }
}
