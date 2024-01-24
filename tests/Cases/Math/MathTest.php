<?php

use CleantalkSP\Common\Scanner\HeuristicAnalyser\Controller;
use CleantalkSP\Common\Scanner\HeuristicAnalyser\Structures\FileInfo;
use PHPUnit\Framework\TestCase;

class ConcatenateTest extends TestCase
{

    public function testAnalyse()
    {
        $current_dir = __DIR__ . DIRECTORY_SEPARATOR;

        $heuristic_scanner = new Controller();
        $file_to_check = new FileInfo('bad.php', file_get_contents($current_dir . 'bad.php'));
        $heuristic_scanner->scanFile($file_to_check, $current_dir);

        $compare_res = strpos($heuristic_scanner->final_code, 'BAse64_dEcode');
        $this->assertTrue((bool) $compare_res);
    }
}
