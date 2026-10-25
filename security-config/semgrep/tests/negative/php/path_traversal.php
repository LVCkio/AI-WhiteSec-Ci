<?php
function path() {
    $page = $_GET['page'];
    // ok: team.php.path-taint
    readfile("/var/docs/" . basename($page));
}

// ---- v4.1
function load_config() {
    $cfg = file_get_contents('/etc/app/config.ini');
    require_once __DIR__ . '/lib/functions.php';
    return $cfg;
}
