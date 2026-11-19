<?php
function xss() {
    $name = $_GET['name'];
    echo htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
    echo "<p>Hello</p>";
}

// ---- v4.1
function show_title($row) {
    echo htmlspecialchars($row['title'], ENT_QUOTES, 'UTF-8');
    echo '<td>static</td>';
    echo esc_html($row['name']);
}

// ---- v4.2: PHP template (HTML xen the mo PHP)
?>
// ok: team.php.xss-template-request
<input value="<?= htmlspecialchars($_POST['username'], ENT_QUOTES, 'UTF-8') ?>">
// ok: team.php.xss-template-request
<input type="checkbox" <?= isset($_POST['remember']) && $_POST['remember'] == 1 ? 'checked' : '' ?>>
<td><?= esc_html($row['title']) ?></td>
<td><?= intval($count) ?></td>

// ---- v4.4 (R2): sanitizer bo sung cho team.php.xss-taint
function show_tag_stripped() {
    echo "Modules.php?modname=" . strip_tags(trim($_REQUEST['modname']));
}
function show_message_wp() {
    $msg = $_GET['message'];
    echo esc_html($msg);
}
function show_id_abs() {
    echo absint($_GET['id']);
}
