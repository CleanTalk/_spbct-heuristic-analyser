<?php

namespace CleantalkSP\Common\Scanner\HeuristicAnalyser\Modules;

class CodeStyle
{
    /**
     * @var Tokens
     */
    private $tokens;

    /**
     * @var int shows how many symbols could contains normal code line
     */
    const NORMAL_CODE_STRING_LENGTH = 300;

    /**
     * @var int shows how many symbols could contains normal code line
     */
    const CRITICAL_CODE_STRING_LENGTH = 1000;

    /**
     * Holds all lines length
     * Indexed by line numbers
     *
     * @var int[]
     */
    private $line_lengths = array();

    /**
     *
     * @var int[]
     */
    private $long_line_nums;

    /**
     * Holds numbers of critical long lines
     *
     * @var int[]
     */
    private $critical_long_line_nums = array();

    /**
     * Check if file contains unreadable code
     */
    private $is_unreadable = false;

    /**
     * Line numbers with tokens which should be on a different lines
     *
     * @var array
     */
    private $greedy_token_lines = array();

    /**
     * Number of symbols with code|html|comments
     *
     * @var int
     */
    private $length_of_tokens__code = 0;
    private $length_of_tokens__html = 0;
    private $length_of_tokens__comments = 0;

    /**
     * Line numbers with tokens contains code|html|comments
     *
     * @var array
     */
    private $number_of_lines__code = array();
    private $number_of_lines__html = array();
    private $number_of_lines__comments = array();

    public function __construct(Tokens $tokens)
    {
        $this->tokens = $tokens;
    }

    public function analiseLineLengths(&$content)
    {
        $lines = preg_split("/((\r?\n)|(\r\n?))/", $content);

        for ( $line_num = 1; isset($lines[$line_num - 1]); $line_num++ ) {
            $this->line_lengths[$line_num] = strlen($lines[$line_num - 1]);

            if ( $this->line_lengths[$line_num] > self::NORMAL_CODE_STRING_LENGTH ) {
                $this->long_line_nums[] = $line_num;
            }

            if ( $this->line_lengths[$line_num] > self::CRITICAL_CODE_STRING_LENGTH ) {
                $this->critical_long_line_nums[] = $line_num;
            }
        }
    }

    public function analiseUnreadableCode(&$content)
    {
        $proportion_spec_symbols = $this->proportionOfSpecialSymbols($content);
        $weight = $this->getWeightOfRandom($content);

        if ($proportion_spec_symbols <= 3 || $weight > 1 ) {
            $this->is_unreadable = true;
        }
    }

    public function searchIncompatibleOnelinedTokens()
    {
        if ( $this->tokens->current->isTypeOf('one_line') ) {
            $this->greedy_token_lines[] = $this->tokens->current->line;
        }
    }

    public function sortTokensWithDifferentTypes()
    {
        $current_token_length = $this->tokens->current->length;
        $current_token_line   = $this->tokens->current->line;

        if ( $this->tokens->current->isTypeOf('html') ) {
            $this->tokens->html[]          = $this->tokens->current;
            $this->length_of_tokens__html  += $current_token_length;
            $this->number_of_lines__html[] = $current_token_line;
        } elseif ( $this->tokens->current->isTypeOf('comments') ) {
            $this->tokens->comments[]          = $this->tokens->current;
            $this->length_of_tokens__comments  += $current_token_length;
            $this->number_of_lines__comments[] = $current_token_line;
        } else {
            $this->length_of_tokens__code  += $current_token_length;
            $this->number_of_lines__code[] = $current_token_line;
        }
    }

    public function detectBadLines()
    {
        $line_nums = array_unique($this->critical_long_line_nums);
        $values    = array_fill(0, count($line_nums), 'long line');
        $result    = array_combine($line_nums, $values);

        if ($this->is_unreadable) {
            $result = array_merge($result, [1 => 'unreadable']);
        }

        return $result;
    }

    private function proportionOfSpecialSymbols($content)
    {
        preg_match_all('#[^a-zA-Z\d\s:]#', $content, $symbols);

        if (isset($symbols[0]) && count($symbols[0]) > 0) {
            return strlen($content) / count($symbols[0]);
        }

        return 100;
    }

    private function getWeightOfRandom($content)
    {
        $weight = 0;

        preg_match_all('#[a-zA-Z\d_\-\+]+#', $content, $words);
        $words = isset($words[0]) ? $words[0] : [];

        $words = array_filter($words, function($word) {
            return strlen($word) > 5;
        });
        $words = array_values($words);

        $words_weight = [];
        foreach ($words as $word) {
            $words_weight[$word] = 0;
            if (strpos($word, '+') !== false) {
                $words_weight[$word] += 1;
            }
            $lower_word = strtolower($word);
            if (strlen($lower_word) - similar_text($lower_word, $word) > 3) {
                $words_weight[$word] += 1;
            }
            if (preg_match('#[^\d]\d+[\w]#', $word)) {
                $words_weight[$word] += 1;
            }
        }

        if (count($words_weight) > 0) {
            $weight = array_sum(array_values($words_weight)) / count($words_weight);
        }

        return $weight;
    }
}
