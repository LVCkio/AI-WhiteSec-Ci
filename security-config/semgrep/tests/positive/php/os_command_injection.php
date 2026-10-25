<?php
function cmd() {
    $host = $_REQUEST['host'];
    // ruleid: team.php.cmdi-taint, team.php.cmd-dynamic
    $out = shell_exec("ping -c 1 " . $host);
}

// ---- v4.1
function convert($cmd, $file) {
    // ruleid: team.php.audit.process-api
    exec($cmd, $out);
    // ruleid: team.php.audit.process-api
    $safe = escapeshellcmd($file);
}
