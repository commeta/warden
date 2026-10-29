<?php
// Warden Lab microservice — PHP-FPM. Same contract as the other runtimes,
// served by its own FPM pool (its own user) behind the front's FastCGI route.
declare(strict_types=1);
$ROOT = getenv('LAB_ROOT') ?: dirname(__DIR__);
$UPLOADS = $ROOT . '/uploads';
$DB = $ROOT . '/data/items.sqlite';
$path = preg_replace('#^/svc/[^/]+#', '', parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH)) ?: '/';
header('X-Lab-Service: php-fpm');
header('Content-Type: text/plain; charset=utf-8');
switch ($path) {
    case '/health': echo 'ok'; break;
    case '/echo': echo 'echo: ' . ($_GET['q'] ?? ''); break;    // XSS target
    case '/item':
        $id = (string)($_GET['id'] ?? '1');
        try {
            $db = new PDO('sqlite:' . $DB, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_SILENT]);
            $r = @$db->query("SELECT id,name,note FROM items WHERE id = $id");   // SQLi target, read-only db
            $out = [];
            if ($r) foreach ($r as $row) $out[] = "{$row['id']}|{$row['name']}|{$row['note']}";
            echo $out ? implode("\n", $out) : 'no result';
        } catch (Throwable $e) { echo 'error'; }
        break;
    case '/spawn': echo shell_exec('/usr/bin/id') . 'spawned'; break;  // web_spawn target
    case '/sleep': $ms = min((int)($_GET['ms'] ?? 0), 10000); usleep($ms * 1000); echo 'slept'; break;
    case '/alloc': $mb = max(1, min((int)($_GET['mb'] ?? 1), 256)); $s = str_repeat("\x01", $mb*1024*1024); echo 'alloc ' . $mb . ' (' . strlen($s) . ')'; break;
    case '/upload':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') { http_response_code(405); echo 'POST'; break; }
        @mkdir($UPLOADS, 0750, true);
        $name = preg_replace('/[^A-Za-z0-9._-]/', '_', (string)($_GET['name'] ?? 'upload.bin'));
        file_put_contents($UPLOADS . '/' . $name, substr((string)file_get_contents('php://input'), 0, 262144));
        echo 'stored uploads/' . $name;
        break;
    default: http_response_code(404); echo 'not found';
}
