<?php
function sqli($conn) {
    $n = intval($_GET['n']);
    // ok: team.php.sqli-taint
    $r = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $n);
    // ok: team.php.sqli-taint, team.php.sqli-string
    $stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
}

// ---- v4.1
function find_user($wpdb, $stmt, $select, $id) {
    // ok: team.php.audit.sql-api
    $rows = $wpdb->get_results('SELECT * FROM users');
    // ok: team.php.audit.sql-api
    $select->where('id', $id);
    // ok: team.php.audit.sql-api
    $stmt->execute([$id]);
}

// ---- v4.5: constant SQL and named bindings; dynamic SELECT/table are outside this rule.
function query_single_bound($DB, $email, $column, $table) {
    // ok: team.php.audit.query-single-dynamic-where
    $DB->query_single('username', 'users', 'email = :email', null, array(':email'=>$email));
    // ok: team.php.audit.query-single-dynamic-where
    $DB->query_single('id', 'users', 'enabled = 1');
    $where = 'email = :email';
    // ok: team.php.audit.query-single-dynamic-where
    $DB->query_single('id', 'users', $where, null, array(':email'=>$email));
    // ok: team.php.audit.query-single-dynamic-where
    $DB->query_single($column, $table, 'enabled = 1');
    // ok: team.php.audit.query-single-dynamic-where
    $DB->query_single('id', 'users');
}
function unrelated_query_single($service, $id) {
    // ok: team.php.audit.query-single-dynamic-where
    $service->query_single('id', 'users', 'id = '.$id);
}

function numeric_where($DB, $id, $site) {
    // ok: team.php.audit.query-single-dynamic-where
    $DB->query_single('id', 'users', 'id = '.intval($id).' AND site = '.intval($site));
    // ok: team.php.audit.query-single-dynamic-where
    $DB->query_single('id', 'users', 'id = '.((int) $id));
    // ok: team.php.audit.query-single-dynamic-where
    $DB->query_single('id', 'users', 'score > '.floatval($id));
}
