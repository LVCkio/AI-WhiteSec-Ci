<?php
function xss() {
    $name = $_GET['name'];
    // ok: team.php.xss-taint
    echo htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
    // ok: team.php.xss-taint, team.php.xss-html-concat
    echo "<p>Hello</p>";
}

// ---- v4.1
function show_title($row) {
    // ok: team.php.audit.echo-unescaped
    echo htmlspecialchars($row['title'], ENT_QUOTES, 'UTF-8');
    // ok: team.php.audit.echo-unescaped
    echo '<td>static</td>';
    // ok: team.php.audit.echo-unescaped
    echo esc_html($row['name']);
}

// ---- v4.2: PHP template (HTML xen the mo PHP)
?>
// ok: team.php.xss-template-request, team.php.audit.xss-template-echo
<input value="<?= htmlspecialchars($_POST['username'], ENT_QUOTES, 'UTF-8') ?>">
// ok: team.php.xss-template-request
<input type="checkbox" <?= isset($_POST['remember']) && $_POST['remember'] == 1 ? 'checked' : '' ?>>
// ok: team.php.audit.xss-template-echo
<td><?= esc_html($row['title']) ?></td>
// ok: team.php.audit.xss-template-echo
<td><?= intval($count) ?></td>
