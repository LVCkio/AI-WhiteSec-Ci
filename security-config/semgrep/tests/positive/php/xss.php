<?php
function xss() {
    $name = $_GET['name'];
    echo "<p>Hello " . $name . "</p>";
}

// ---- v4.1
function show_title($row) {
    echo $row['title'];
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
<td><?= $row['title'] ?></td>
<span><?php echo $user->name; ?></span>
