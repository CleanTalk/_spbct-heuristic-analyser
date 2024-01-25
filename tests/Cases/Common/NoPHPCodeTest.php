<?php

use CleantalkSP\Common\Scanner\HeuristicAnalyser\Controller;
use CleantalkSP\Common\Scanner\HeuristicAnalyser\Structures\FileInfo;
use PHPUnit\Framework\TestCase;

class NoPHPCodeTest extends TestCase
{
    private $current_dir;
    private $heuristic_scanner;

    private $files_list;

    public function setUp()
    {
        $this->current_dir = __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR;
        $this->heuristic_scanner = new Controller();
        $this->files_list = array(
            'testNoPHPCodeFile' => new FileInfo(
                'has_no_php.otf',
                file_get_contents($this->current_dir . 'has_no_php.otf')
            ),
            'testNoPHPCodeFileWithShortOpenTag' => new FileInfo(
                'has_no_php_but_has_short_open_tag.otf',
                file_get_contents($this->current_dir . 'has_no_php_but_has_short_open_tag.otf')
            ),
            'testHasPHPCodeBadFile' => new FileInfo(
                'has_bad_php.otf',
                file_get_contents($this->current_dir . 'has_bad_php.otf')
            ),
            'testHasPHPCodeBadFileShortOpenTag' => new FileInfo(
                'has_bad_php_short_tag.otf',
                file_get_contents($this->current_dir . 'has_bad_php_short_tag.otf')
            ),
            'testHasPHPCodeBadFileNoClosingTag' => new FileInfo(
                'has_bad_php_no_closing_tag.otf',
                file_get_contents($this->current_dir . 'has_bad_php_no_closing_tag.otf')
            ),
            'testHasPHPCodeBadFileOpenSomewhere' => new FileInfo(
                'has_bad_php_open_somewhere.otf',
                file_get_contents($this->current_dir . 'has_bad_php_open_somewhere.otf')
            ),
            'testHasPHPCodeGoodFile' => new FileInfo(
                'has_good_php.otf',
                file_get_contents($this->current_dir . 'has_good_php.otf')
            ),
        );
        parent::setUp(); // TODO: Change the autogenerated stub
    }

    public function testNoPHPCodeFile()
    {
        $verdict = $this->heuristic_scanner->scanFile($this->files_list[__FUNCTION__], $this->current_dir);
        $this->assertEquals('OK', $verdict->status);
        $this->assertEquals(null, $verdict->severity);
    }

    public function testNoPHPCodeFileWithShortOpenTag()
    {
        $verdict = $this->heuristic_scanner->scanFile($this->files_list[__FUNCTION__], $this->current_dir);
        $this->assertEquals('OK', $verdict->status);
        $this->assertEquals(null, $verdict->severity);
    }
    public function testHasPHPCodeBadFile()
    {
        $verdict = $this->heuristic_scanner->scanFile($this->files_list[__FUNCTION__], $this->current_dir);
        $this->assertEquals('INFECTED', $verdict->status);
        $this->assertEquals('SUSPICIOUS', $verdict->severity);
    }

    public function testHasPHPCodeBadFileNoClosingTag()
    {
        $verdict = $this->heuristic_scanner->scanFile($this->files_list[__FUNCTION__], $this->current_dir);
        $this->assertEquals('INFECTED', $verdict->status);
        $this->assertEquals('SUSPICIOUS', $verdict->severity);
    }

    public function testHasPHPCodeBadFileOpenSomewhere()
    {
        $verdict = $this->heuristic_scanner->scanFile($this->files_list[__FUNCTION__], $this->current_dir);
        $this->assertEquals('INFECTED', $verdict->status);
        $this->assertEquals('SUSPICIOUS', $verdict->severity);
    }

    public function testHasPHPCodeBadFileShortOpenTag()
    {
        $verdict = $this->heuristic_scanner->scanFile($this->files_list[__FUNCTION__], $this->current_dir);
        $this->assertEquals('INFECTED', $verdict->status);
        $this->assertEquals('SUSPICIOUS', $verdict->severity);
    }

    public function testHasPHPCodeGoodFile()
    {
        $verdict = $this->heuristic_scanner->scanFile($this->files_list[__FUNCTION__], $this->current_dir);
        $this->assertEquals('OK', $verdict->status);
        $this->assertEquals(null, $verdict->severity);
    }
}