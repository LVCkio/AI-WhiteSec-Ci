<?php
function cmd() {
    $host = $_REQUEST['host'];
    // ok: team.php.cmdi-taint, team.php.cmd-dynamic
    $out = shell_exec("ping -c 1 " . escapeshellarg($host));
    // ok: team.php.cmdi-taint, team.php.cmd-dynamic
    $up = shell_exec("uptime");
}

// ---- v4.1
function convert() {
    // ok: team.php.audit.process-api
    exec('uptime', $out);
}
