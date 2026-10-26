<?php
function xss() {
    $name = $_GET['name'];
    // ruleid: team.php.xss-taint
    echo "<p>Hello " . $name . "</p>";
}

// ---- v4.1
function show_title($row) {
    // ruleid: team.php.audit.echo-unescaped
    echo $row['title'];
    // ruleid: team.php.audit.echo-unescaped
    echo '<td>' . $row['name'] . '</td>';
}

// ---- v4.2: PHP template (HTML xen the mo PHP), file mau thuong khong parse duoc bang parser PHP
?>
// ruleid: team.php.xss-template-request
<input type="text" name="username" value="<?= isset($_POST['username']) ? $_POST['username'] : '' ?>">
// ruleid: team.php.xss-template-request
<form action="<?php echo $_SERVER['PHP_SELF']; ?>" method="post">
// ruleid: team.php.xss-template-request
<b><?= ucfirst($_GET['editLang']) ?></b>
// ruleid: team.php.audit.xss-template-echo
<td><?= $row['title'] ?></td>
// ruleid: team.php.audit.xss-template-echo
<span><?php echo $user->name; ?></span>
