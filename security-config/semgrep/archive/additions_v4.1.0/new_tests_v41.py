A = {}  # (kind, lang, class_file) -> text appended to the existing test file
# ----------------------------------------------------------------- JavaScript
A[("positive", "javascript", "xss")] = '''
// ---- v4.1
function renderRow(container, name) {
  // ruleid: team.js.xss-jquery-insert
  container.append('<li>' + name + '</li>');
  // ruleid: team.js.xss-jquery-insert
  $('#list').prepend(html);
}
'''
A[("negative", "javascript", "xss")] = '''
// ---- v4.1
function renderRow(container, name, formData) {
  // ok: team.js.xss-jquery-insert
  container.append('<li>static</li>');
  // ok: team.js.xss-jquery-insert
  container.append(document.createTextNode(name));
  // ok: team.js.xss-jquery-insert
  formData.append('name', name);
}
'''
A[("positive", "javascript", "sql_injection")] = '''
// ---- v4.1
async function findUser(pool, name, id) {
  // ruleid: team.js.sqli-dynamic-query
  await pool.query("SELECT * FROM users WHERE name = '" + name + "'");
  // ruleid: team.js.sqli-dynamic-query
  await sequelize.query(`DELETE FROM sessions WHERE uid = ${id}`);
  // ruleid: team.js.sqli-dynamic-query
  return Sequelize.literal('(SELECT COUNT(*) FROM posts WHERE owner = ' + id + ')');
}
'''
A[("negative", "javascript", "sql_injection")] = '''
// ---- v4.1
async function findUser(pool, name, cache, a, b) {
  // ok: team.js.sqli-dynamic-query
  await pool.query("SELECT * FROM users WHERE name = $1", [name]);
  // ok: team.js.sqli-dynamic-query
  const total = cache.get(a + b);
  return total;
}
'''
A[("positive", "javascript", "path_traversal")] = '''
// ---- v4.1
function readUpload(name, res) {
  // ruleid: team.js.audit.fs-path-api
  const data = fs.readFileSync(path.join(UPLOAD_DIR, name));
  // ruleid: team.js.audit.fs-path-api
  fs.unlink(name, () => {});
  // ruleid: team.js.audit.fs-path-api
  res.download(name);
}
'''
A[("negative", "javascript", "path_traversal")] = '''
// ---- v4.1
function readConfig(res) {
  // ok: team.js.audit.fs-path-api
  const data = fs.readFileSync("/etc/app/config.json");
  // ok: team.js.audit.fs-path-api
  res.sendFile("index.html");
  return data;
}
'''
A[("positive", "javascript", "os_command_injection")] = '''
// ---- v4.1
function build(cmd, target) {
  // ruleid: team.js.audit.process-api
  child.exec(cmd);
  // ruleid: team.js.audit.process-api
  execSync(target);
}
'''
A[("negative", "javascript", "os_command_injection")] = '''
// ---- v4.1
function build(text) {
  // ok: team.js.audit.process-api
  cp.exec("make all");
  // ok: team.js.audit.process-api
  const m = /a(b)/.exec(text);
  return m;
}
'''
A[("positive", "javascript", "authentication_weakness")] = '''
// ---- v4.1
// ruleid: team.js.audit.auth-code
function verifyPassword(user, password) {
  return user.password === hash(password);
}

app.post('/login', (req, res) => {
  // ruleid: team.js.audit.auth-code
  req.session.user = req.body.username;
});
'''
A[("negative", "javascript", "authentication_weakness")] = '''
// ---- v4.1
// ok: team.js.audit.auth-code
function renderPage(title) {
  return title;
}

app.get('/theme', (req, res) => {
  // ok: team.js.audit.auth-code
  req.session.theme = req.query.theme;
});
'''
# ----------------------------------------------------------------------- PHP
A[("positive", "php", "path_traversal")] = '''
// ---- v4.1
function load_template($name) {
    // ruleid: team.php.audit.file-path-api
    $tpl = file_get_contents($this->dir . '/' . $name);
    // ruleid: team.php.audit.file-path-api
    include $name;
    return $tpl;
}
'''
A[("negative", "php", "path_traversal")] = '''
// ---- v4.1
function load_config() {
    // ok: team.php.audit.file-path-api
    $cfg = file_get_contents('/etc/app/config.ini');
    // ok: team.php.audit.file-path-api
    require_once __DIR__ . '/lib/functions.php';
    return $cfg;
}
'''
A[("positive", "php", "xss")] = '''
// ---- v4.1
function show_title($row) {
    // ruleid: team.php.audit.echo-unescaped
    echo $row['title'];
    // ruleid: team.php.audit.echo-unescaped
    echo '<td>' . $row['name'] . '</td>';
}
'''
A[("negative", "php", "xss")] = '''
// ---- v4.1
function show_title($row) {
    // ok: team.php.audit.echo-unescaped
    echo htmlspecialchars($row['title'], ENT_QUOTES, 'UTF-8');
    // ok: team.php.audit.echo-unescaped
    echo '<td>static</td>';
    // ok: team.php.audit.echo-unescaped
    echo esc_html($row['name']);
}
'''
A[("positive", "php", "sql_injection")] = '''
// ---- v4.1
function find_user($wpdb, $zdb, $select, $id) {
    // ruleid: team.php.audit.sql-api
    $rows = $wpdb->get_results("SELECT * FROM users WHERE id = " . $id);
    // ruleid: team.php.audit.sql-api
    $select->where("id = " . $id);
    // ruleid: team.php.audit.sql-api
    $zdb->execute($select);
}
'''
A[("negative", "php", "sql_injection")] = '''
// ---- v4.1
function find_user($wpdb, $stmt, $select, $id) {
    // ok: team.php.audit.sql-api
    $rows = $wpdb->get_results('SELECT * FROM users');
    // ok: team.php.audit.sql-api
    $select->where('id', $id);
    // ok: team.php.audit.sql-api
    $stmt->execute([$id]);
}
'''
A[("positive", "php", "os_command_injection")] = '''
// ---- v4.1
function convert($cmd, $file) {
    // ruleid: team.php.audit.process-api
    exec($cmd, $out);
    // ruleid: team.php.audit.process-api
    $safe = escapeshellcmd($file);
}
'''
A[("negative", "php", "os_command_injection")] = '''
// ---- v4.1
function convert() {
    // ok: team.php.audit.process-api
    exec('uptime', $out);
}
'''
A[("positive", "php", "authentication_weakness")] = '''
// ---- v4.1
// ruleid: team.php.audit.auth-code
function checkLogin($user, $password) {
    return false;
}

function start($user) {
    // ruleid: team.php.audit.auth-code
    $_SESSION['user_id'] = $user;
}
'''
A[("negative", "php", "authentication_weakness")] = '''
// ---- v4.1
// ok: team.php.audit.auth-code
function renderPage($title) {
    return $title;
}

function theme($t) {
    // ok: team.php.audit.auth-code
    $_SESSION['theme'] = $t;
}
'''
# ---------------------------------------------------------------------- Java
A[("positive", "java", "xss")] = '''
// ---- v4.1
class XssPositiveV41 {
    void render(XMLWriter xmlWriter, String title, Element el) {
        // ruleid: team.java.xss-writer-output
        xmlWriter.write(title);
        // ruleid: team.java.xss-writer-output
        getPrinter().print(title);
        // ruleid: team.java.xss-writer-output
        el.html(title);
    }
}
'''
A[("negative", "java", "xss")] = '''
// ---- v4.1
class XssNegativeV41 {
    void render(XMLWriter xmlWriter, String title, Element el, StringBuilder sb) {
        // ok: team.java.xss-writer-output
        xmlWriter.write("<br/>");
        // ok: team.java.xss-writer-output
        System.out.println(title);
        // ok: team.java.xss-writer-output
        el.text(title);
    }
}
'''
A[("positive", "java", "os_command_injection")] = '''
// ---- v4.1
class CmdPositiveV41 {
    void run(String exe, String file) {
        // ruleid: team.java.audit.commandline-api
        CommandLine cl = new CommandLine(exe);
        // ruleid: team.java.audit.commandline-api
        cl.addArgument(file);
    }
}
'''
A[("negative", "java", "os_command_injection")] = '''
// ---- v4.1
class CmdNegativeV41 {
    void run() {
        // ok: team.java.audit.commandline-api
        CommandLine cl = new CommandLine("git");
        // ok: team.java.audit.commandline-api
        cl.addArgument("status");
    }
}
'''
# -------------------------------------------------------------------- Python
A[("positive", "python", "path_traversal")] = '''

# ---- v4.1
def save(name, tmp):
    # ruleid: team.py.audit.pathlib-api
    target = Path(name)
    # ruleid: team.py.audit.pathlib-api
    shutil.move(tmp, name)
    return target
'''
A[("negative", "python", "path_traversal")] = '''

# ---- v4.1
def config_path():
    # ok: team.py.audit.pathlib-api
    here = Path(__file__)
    # ok: team.py.audit.pathlib-api
    cfg = Path("/etc/app/config.ini")
    return here, cfg
'''
A[("positive", "python", "xss")] = '''

# ---- v4.1
def make_env(loader, body):
    # ruleid: team.py.xss-jinja-autoescape-default
    env = jinja2.Environment(loader=loader)
    # ruleid: team.py.audit.response-body
    return flask.Response(body, mimetype="text/html")
'''
A[("negative", "python", "xss")] = '''

# ---- v4.1
def make_env(loader, data):
    # ok: team.py.xss-jinja-autoescape-default
    env = jinja2.Environment(loader=loader, autoescape=True)
    # ok: team.py.audit.response-body
    return flask.Response(json.dumps(data), mimetype="application/json")
'''
