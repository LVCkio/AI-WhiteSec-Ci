<?php
function auth($user, $stored) {
    $pass = $_POST['password'];
    // ruleid: team.php.auth-weak-password-hash
    $h = md5($pass);
    if ($pass == $stored) { return true; }
    return false;
}

// ---- v4.1
// ruleid: team.php.audit.auth-code
function checkLogin($user, $password) {
    return false;
}

function start($user) {
    // ruleid: team.php.audit.auth-code
    $_SESSION['user_id'] = $user;
}
