<?php
function path() {
    $page = $_GET['page'];
    // ruleid: team.php.path-taint
    include $page;
}

// ---- v4.1
function load_template($name) {
    $tpl = file_get_contents($this->dir . '/' . $name);
    unlink($name);
    return $tpl;
}
