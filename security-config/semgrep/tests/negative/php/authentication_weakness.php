<?php
function auth($user, $stored, $not_pass_update, $passport) {
    $pass = $_POST['password'];
    // ok: team.php.auth-weak-password-hash
    $id = md5($user);
    // ok: team.php.auth-weak-password-hash
    $p = md5($passport);
    if ($not_pass_update == false) { return false; }
    if ($token_type === "bearer") { return false; }
    return password_verify($pass, $stored);
}

// ---- v4.1
// retired audit rule assertion retained in tests_disabled/
function renderPage($title) {
    return $title;
}

function theme($t) {
    // retired audit rule assertion retained in tests_disabled/
    $_SESSION['theme'] = $t;
}
