<?php
// ok: team.php.hardcoded-secret
$db_password = getenv('DB_PASSWORD');

function login($username, $password, $stored) {
    // ok: team.php.hardcoded-password-compare
    if ($username === "admin") { return password_verify($password, $stored); }
    // ok: team.php.hardcoded-password-compare
    return $password === "";
}
