<?php
function sqli($conn) {
    $id = $_GET['id'];
    // ruleid: team.php.sqli-taint, team.php.sqli-string
    $r = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
    $n = intval($_GET['n']);
    // ruleid: team.php.sqli-string
    $r2 = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $n);
}

// ---- v4.1
function find_user($wpdb, $zdb, $select, $id) {
    // ruleid: team.php.audit.sql-api
    $rows = $wpdb->get_results("SELECT * FROM users WHERE id = " . $id);
    // ruleid: team.php.audit.sql-api
    $select->where("id = " . $id);
    // ruleid: team.php.audit.sql-api
    $zdb->execute($select);
}
