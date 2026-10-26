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

// ---- v4.5: query_single uses WHERE argument 3, not SELECT or table.
function query_single_unsafe($DB, $email, $reference, $website) {
    // ruleid: team.php.audit.query-single-dynamic-where
    $DB->query_single('username', 'users', 'email = '.protect($email));
    // ruleid: team.php.audit.query-single-dynamic-where
    $DB->query_single('id', 'orders', 'reference = '.protect($reference).' AND website = '.$website);
    $where = 'email = '.protect($email);
    // ruleid: team.php.audit.query-single-dynamic-where
    $DB->query_single('id', 'users', $where);
}
class DynamicWhereV45 {
    function find($id) {
        // ruleid: team.php.audit.query-single-dynamic-where
        return $this->db->query_single('id', 'users', 'id = '.$id, null, []);
    }
}

function mixed_where($DB, $id, $email) {
    // ruleid: team.php.audit.query-single-dynamic-where
    $DB->query_single('id', 'users', 'id = '.intval($id).' AND email = '.$email);
}
