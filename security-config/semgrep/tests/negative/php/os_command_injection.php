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

// ---- v4.5: quote at append, constants, reset, and unrelated executors.
class GitPhpQuotedV45 {
    function quoted($tree, $type, $id, $path) {
        $args = array();
        // ok: team.php.audit.gitphp-unescaped-argument
        $args[] = '--tags';
        // ok: team.php.audit.gitphp-unescaped-argument
        $args[] = escapeshellarg($tree->GetHash());
        // ok: team.php.audit.gitphp-unescaped-argument
        $args[] = '--'.escapeshellarg($type);
        // ok: team.php.audit.gitphp-unescaped-argument
        $args[] = intval($id);
        // ok: team.php.audit.gitphp-unescaped-argument
        $args[] = (int) $id;
        $this->exe->Execute('/repos/demo', GIT_NAME_REV, $args);
        $this->exe->Execute($path, GIT_NAME_REV, array('--tags'));
    }
    function constants() {
        $args = array();
        // ok: team.php.audit.gitphp-unescaped-argument
        $args[] = '--tags';
        // ok: team.php.audit.gitphp-unescaped-argument
        $args[] = 1;
        $this->exe->Execute('/repos/demo', GIT_NAME_REV, $args);
    }
    function reset_args($hash) {
        $args = array();
        // ok: team.php.audit.gitphp-unescaped-argument
        $args[] = $hash;
        $args = array('--tags');
        $this->exe->Execute('/repos/demo', GIT_NAME_REV, $args);
    }
    function unrelated($hash) {
        $args = array();
        // ok: team.php.audit.gitphp-unescaped-argument
        $args[] = $hash;
        $this->db->Execute('/repos/demo', GIT_NAME_REV, $args);
        $this->exe->Execute('/repos/demo', SQL_SELECT, $args);
    }
}
