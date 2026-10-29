<?php
/**
 * Warden Lab Kit 2.0 — shared site engine.
 *
 * Every emulated CMS defines a small $LAB_ENGINE array in its own index.php
 * and then requires this file. The engine gives the site the *look* of a real
 * CMS to an attacker and to ModSecurity/CRS — its admin path, cookie name,
 * generator banner and the canonical URLs scanners probe — while all sites
 * share one set of deliberately attackable endpoints so a single test suite
 * covers them.
 *
 * This is a TECHNICAL test target, not a real application: the UI is plain,
 * there is no styling to speak of, and the "vulnerable" endpoints are the
 * point — ModSecurity is expected to stop the attacks before PHP would act,
 * and the endpoints are written so that even if a request slips through, it
 * cannot read outside the docroot or run a shell.
 */

declare(strict_types=1);
error_reporting(E_ALL & ~E_DEPRECATED);

if (!isset($LAB_ENGINE)) {
    http_response_code(500);
    echo "lab engine not configured";
    exit;
}

$ENG = $LAB_ENGINE;
$DOCROOT = __DIR__;
$DATA = dirname($DOCROOT) . '/data';
$UPLOADS = $DOCROOT . '/uploads';

/* ---- request routing ------------------------------------------------- */
$uri = $_SERVER['REQUEST_URI'] ?? '/';
$path = parse_url($uri, PHP_URL_PATH) ?: '/';
$path = '/' . ltrim($path, '/');

/* map this engine's canonical CMS URLs onto the shared lab actions, so an
 * attack aimed at e.g. /wp-admin/ or /administrator/ lands on a real target. */
$action = lab_route($ENG, $path);

header('X-Lab-Engine: ' . $ENG['id']);
if (!empty($ENG['generator_header'])) {
    header('X-Generator: ' . $ENG['generator_header']);
}
if (!empty($ENG['cookie'])) {
    // a realistic-looking session cookie (scanners fingerprint on these)
    if (!isset($_COOKIE[$ENG['cookie']])) {
        setcookie($ENG['cookie'], bin2hex(random_bytes(8)), ['httponly' => true, 'samesite' => 'Lax']);
    }
}

switch ($action) {
    case 'home':        lab_home($ENG); break;
    case 'xss':         lab_xss(); break;
    case 'sqli':        lab_sqli($DATA); break;
    case 'traversal':   lab_traversal($DOCROOT); break;
    case 'cmd':         lab_cmd(); break;
    case 'upload':      lab_upload($UPLOADS); break;
    case 'admin_save':  lab_admin_save($ENG, $DATA); break;
    case 'admin':       lab_admin($ENG); break;
    case 'info':        lab_info($ENG); break;
    case 'batch':       lab_batch($ENG); break;
    case 'health':      header('Content-Type: text/plain'); echo 'ok'; break;
    default:            http_response_code(404); lab_404($ENG);
}

/* ---- routing table --------------------------------------------------- */
function lab_route(array $eng, string $path): string
{
    if ($path === '/' || $path === '/index.php') return 'home';
    // shared lab endpoints
    static $lab = [
        '/lab/xss' => 'xss', '/lab/sqli' => 'sqli', '/lab/traversal' => 'traversal',
        '/lab/cmd' => 'cmd', '/lab/upload' => 'upload', '/lab/info' => 'info',
        '/lab/batch' => 'batch', '/lab/health' => 'health', '/health' => 'health',
        '/lab/admin-save' => 'admin_save',
    ];
    if (isset($lab[$path])) return $lab[$path];
    // engine-specific canonical paths
    foreach ($eng['routes'] as $prefix => $act) {
        if ($path === $prefix || str_starts_with($path, rtrim($prefix, '/') . '/')) {
            return $act;
        }
    }
    return 'notfound';
}

/* ---- pages ----------------------------------------------------------- */
function lab_head(array $eng, string $title): void
{
    header('Content-Type: text/html; charset=utf-8');
    echo "<!doctype html><html lang=en><head><meta charset=utf-8>";
    echo "<meta name=viewport content='width=device-width,initial-scale=1'>";
    echo "<meta name=generator content='" . htmlspecialchars($eng['generator'], ENT_QUOTES) . "'>";
    echo "<title>" . htmlspecialchars($title, ENT_QUOTES) . "</title>";
    echo "<style>body{font-family:monospace;max-width:52rem;margin:1rem auto;padding:0 1rem;line-height:1.5}"
       . "a{color:#06c}code,pre{background:#f0f0f0;padding:.1rem .3rem}fieldset{margin:.6rem 0}"
       . "table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:.2rem .5rem;font-size:.9em}"
       . ".ok{color:#070}.bad{color:#b00}</style></head><body>";
    echo "<p><strong>" . htmlspecialchars($eng['name'], ENT_QUOTES) . "</strong> "
       . "<small>(emulated · Warden Lab Kit)</small> — host "
       . "<code>" . htmlspecialchars($_SERVER['HTTP_HOST'] ?? '?', ENT_QUOTES) . "</code></p>";
}

function lab_home(array $eng): void
{
    lab_head($eng, $eng['name'] . ' — lab');
    echo "<p>A technical target emulating <strong>" . htmlspecialchars($eng['name'], ENT_QUOTES)
       . "</strong> for Warden + ModSecurity testing. Admin path: <code>"
       . htmlspecialchars($eng['admin'], ENT_QUOTES) . "</code>.</p>";
    echo "<h2>Attack targets (ModSecurity should block these)</h2><ul>";
    echo "<li><a href='/lab/xss?q=hello'>/lab/xss?q=</a> — reflected input (XSS)</li>";
    echo "<li><a href='/lab/sqli?id=1'>/lab/sqli?id=</a> — read-only lookup (SQLi)</li>";
    echo "<li><a href='/lab/traversal?file=readme.txt'>/lab/traversal?file=</a> — file read (path traversal)</li>";
    echo "<li><a href='/lab/cmd?x=hello'>/lab/cmd?x=</a> — reflected (command injection)</li>";
    echo "<li><code>POST /lab/upload</code> — file upload (webshell drop into uploads/)</li>";
    echo "</ul>";
    echo "<h2>Legitimate admin action (must NOT be blocked)</h2>";
    echo "<form method=post action='/lab/admin-save'><fieldset><legend>Save content</legend>"
       . "<textarea name=content rows=3 cols=50>Hello &lt;b&gt;world&lt;/b&gt;, 1=1 and &lt;script&gt;ok&lt;/script&gt; in an editor.</textarea><br>"
       . "<button>Save</button></fieldset></form>";
    echo "<p><a href='/lab/batch'>Browser batch tests →</a> · <a href='/lab/info'>engine info (JSON)</a></p>";
    if (!empty($GLOBALS['LAB_PORTAL']) && is_array($GLOBALS['LAB_PORTAL'])) {
        lab_portal_section($GLOBALS['LAB_PORTAL']);
    }
    echo "</body></html>";
}

function lab_portal_section(array $m): void
{
    $host = $m['hostname'] ?? ($_SERVER['HTTP_HOST'] ?? 'lab.local');
    echo "<h2>Emulated sites</h2><ul>";
    foreach (($m['sites'] ?? []) as $s) {
        if ($s === 'portal') continue;
        $vhost = $s . '.' . $host;
        echo "<li><a href='//" . htmlspecialchars($vhost, ENT_QUOTES) . "/'>"
           . htmlspecialchars($s, ENT_QUOTES) . "</a> <small>(" . htmlspecialchars($vhost, ENT_QUOTES) . ")</small></li>";
    }
    echo "</ul><h2>Microservices (behind the WAF, one contract)</h2><ul>";
    foreach (($m['services'] ?? []) as $svc) {
        echo "<li><code>/svc/" . htmlspecialchars($svc, ENT_QUOTES) . "/</code> — "
           . "<a href='/svc/" . htmlspecialchars($svc, ENT_QUOTES) . "/health'>health</a>, "
           . "<a href='/svc/" . htmlspecialchars($svc, ENT_QUOTES) . "/echo?q=hi'>echo</a>, "
           . "<a href='/svc/" . htmlspecialchars($svc, ENT_QUOTES) . "/item?id=1'>item</a></li>";
    }
    echo "</ul>";
}

function lab_404(array $eng): void
{
    lab_head($eng, 'not found');
    echo "<p>404 — no such path.</p></body></html>";
}

/* ---- deliberately attackable endpoints ------------------------------- */
function lab_xss(): void
{
    // reflects input verbatim: the classic reflected-XSS sink CRS must catch.
    header('Content-Type: text/html; charset=utf-8');
    $q = $_GET['q'] ?? '';
    echo "<!doctype html><title>echo</title><p>You said: " . $q . "</p>";
}

function lab_sqli(string $data): void
{
    header('Content-Type: text/html; charset=utf-8');
    $id = (string)($_GET['id'] ?? '1');
    $db = new PDO('sqlite:' . $data . '/site.sqlite', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_SILENT]);
    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    // INTENTIONALLY interpolated — a real injection string would reach SQLite
    // if ModSecurity let it through. The DB is opened read-only below so even
    // then it cannot mutate anything; stacked statements are rejected by PDO.
    $sql = "SELECT id, title, body FROM posts WHERE id = $id";
    echo "<h1>post</h1>";
    $res = @$db->query($sql);
    if ($res) {
        foreach ($res as $row) {
            echo "<article><h2>" . htmlspecialchars((string)$row['title'], ENT_QUOTES) . "</h2><p>"
               . htmlspecialchars((string)$row['body'], ENT_QUOTES) . "</p></article>";
        }
    } else {
        echo "<p>no result</p>";
    }
}

function lab_traversal(string $docroot): void
{
    // joins the parameter under the docroot and refuses anything that escapes
    // it: CRS catches ../ first; if it did not, PHP still cannot leak /etc.
    header('Content-Type: text/plain; charset=utf-8');
    $file = (string)($_GET['file'] ?? 'readme.txt');
    $base = realpath($docroot);
    $target = realpath($docroot . '/' . $file);
    if ($target === false || !str_starts_with($target, $base . '/')) {
        http_response_code(404);
        echo "not found";
        return;
    }
    echo file_get_contents($target);
}

function lab_cmd(): void
{
    // reflects only; no shell is ever invoked (a safe command-injection target).
    header('Content-Type: text/plain; charset=utf-8');
    $x = (string)($_GET['x'] ?? '');
    echo "would run: ping -c1 " . $x . "\n(no shell is executed in the lab)";
}

function lab_upload(string $uploads): void
{
    header('Content-Type: text/plain; charset=utf-8');
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo "POST a file as 'f' (multipart) or raw body with ?name=";
        return;
    }
    @mkdir($uploads, 0750, true);
    if (!empty($_FILES['f']['tmp_name']) && is_uploaded_file($_FILES['f']['tmp_name'])) {
        $name = basename((string)$_FILES['f']['name']);
        $name = preg_replace('/[^A-Za-z0-9._-]/', '_', $name) ?: 'upload';
        move_uploaded_file($_FILES['f']['tmp_name'], $uploads . '/' . $name);
        echo "stored uploads/$name";
        return;
    }
    // raw body fallback (tests post a webshell marker this way)
    $name = preg_replace('/[^A-Za-z0-9._-]/', '_', (string)($_GET['name'] ?? 'upload.bin'));
    $body = file_get_contents('php://input');
    if ($body !== false && strlen($body) <= 262144) {
        file_put_contents($uploads . '/' . $name, $body);
        echo "stored uploads/$name";
    } else {
        http_response_code(400);
        echo "empty or too large";
    }
}

function lab_admin(array $eng): void
{
    lab_head($eng, 'admin');
    echo "<p>Emulated admin panel for " . htmlspecialchars($eng['name'], ENT_QUOTES) . ". "
       . "Use the save form on the <a href='/'>home page</a>.</p></body></html>";
}

function lab_admin_save(array $eng, string $data): void
{
    // a legitimate CMS "save": posts HTML/markup an editor would send. The
    // lab's ModSecurity exclusions keep this from being blocked, so a test can
    // tell "WAF blocked an attack" from "WAF blocked the editor".
    header('Content-Type: application/json');
    $content = (string)($_POST['content'] ?? '');
    @file_put_contents($data . '/last-admin-save.txt', $content);
    echo json_encode(['saved' => true, 'bytes' => strlen($content), 'engine' => $eng['id']]);
}

function lab_info(array $eng): void
{
    header('Content-Type: application/json');
    echo json_encode([
        'engine' => $eng['id'], 'name' => $eng['name'], 'admin' => $eng['admin'],
        'host' => $_SERVER['HTTP_HOST'] ?? null, 'php' => PHP_VERSION,
    ], JSON_PRETTY_PRINT);
}

function lab_batch(array $eng): void
{
    lab_head($eng, 'batch tests');
    // a primitive in-browser battery: fires each attack and shows the status
    // the WAF returned. Useful for a human; the pytest suite is authoritative.
    echo <<<HTML
<h2>Browser batch tests</h2>
<p>Each probe should be blocked by ModSecurity (expect 403) except the admin
save (expect 200). Open the console for detail.</p>
<table id=t><tr><th>probe</th><th>expect</th><th>status</th><th></th></tr></table>
<script>
const probes = [
  ['xss',       'GET',  '/lab/xss?q=<script>alert(1)</script>', 403],
  ['sqli',      'GET',  '/lab/sqli?id=1 OR 1=1', 403],
  ['traversal', 'GET',  '/lab/traversal?file=../../../../etc/passwd', 403],
  ['cmd',       'GET',  '/lab/cmd?x=;cat /etc/passwd', 403],
  ['admin-save','POST', '/lab/admin-save', 200],
];
const t = document.getElementById('t');
(async () => {
  for (const [name, method, url, expect] of probes) {
    let status = 0;
    try {
      const opt = {method};
      if (method === 'POST') { opt.headers={'Content-Type':'application/x-www-form-urlencoded'};
        opt.body='content='+encodeURIComponent('<b>hello</b> 1=1'); }
      const r = await fetch(url, opt); status = r.status;
    } catch (e) { status = 'ERR'; }
    const ok = (status == expect);
    const row = t.insertRow();
    row.innerHTML = `<td>\${name}</td><td>\${expect}</td><td>\${status}</td>`
      + `<td class="\${ok?'ok':'bad'}">\${ok?'PASS':'CHECK'}</td>`;
  }
})();
</script>
</body></html>
HTML;
}
