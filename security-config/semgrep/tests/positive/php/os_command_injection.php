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

// ---- v4.5: simplified train GitPHP pairs; repository Execute joins a shell argument list.
class GitPhpUnsafeV45 {
    function refs($tree) {
        $args = array();
        $args[] = '--tags';
        // ruleid: team.php.audit.gitphp-unescaped-argument
        $args[] = $tree->GetHash();
        $lines = explode("\n", $this->exe->Execute('/repos/demo', GIT_NAME_REV, $args));
    }
    function abbreviated($hash) {
        $args = array();
        $args[] = '--format=format:%h';
        // ruleid: team.php.audit.gitphp-unescaped-argument
        $args[] = $hash;
        return $this->exe->Execute('/repos/demo', GIT_REV_LIST, $args);
    }
    function unsafe_addslashes($search) {
        $args = array();
        // ruleid: team.php.audit.gitphp-unescaped-argument
        $args[] = '"'.addslashes($search).'"';
        $this->exe->Execute('/repos/demo', GIT_GREP, $args);
    }
}
