<?php
// ruleid: team.php.hardcoded-secret
$db_password = 'p@ssw0rd!';
// ruleid: team.php.hardcoded-secret
$_CONFIG['db_password'] = 'hunter22';
// ruleid: team.php.hardcoded-secret
define('API_KEY', 'abc123xyz');
// ruleid: team.php.hardcoded-secret
$pdo = new PDO('mysql:host=db;dbname=app', 'app', 'secret99');

function login($username, $password) {
    // ruleid: team.php.hardcoded-password-compare
    if ($username === "webapp" && $password === "Secret9417!") { return true; }
    return false;
}
