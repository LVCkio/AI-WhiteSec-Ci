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
