<?php
// INTENTIONALLY VULNERABLE: raw numeric parameter interpolation in a SELECT only.
// DB grant is SELECT-only; stacked queries and mutations are not enabled here.
require '/etc/warden-lab/db.php';
header('Content-Type: text/html; charset=utf-8');
$id = substr((string)($_GET['id'] ?? '1'), 0, 80);
try {
    $db = new mysqli(LAB_DB_HOST, LAB_DB_USER, LAB_DB_PASS, LAB_DB_NAME);
    $db->set_charset('utf8mb4');
    $result = $db->query("SELECT id,title,body FROM posts WHERE id = $id");
    echo '<!doctype html><html><body><h1>Read-only SQLi lab</h1>';
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            echo '<article><h2>' . htmlspecialchars($row['title'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</h2><p>' . htmlspecialchars($row['body'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</p></article>';
        }
    }
    echo '</body></html>';
    $db->close();
} catch (Throwable $e) {
    http_response_code(500);
    echo 'Database error';
}
