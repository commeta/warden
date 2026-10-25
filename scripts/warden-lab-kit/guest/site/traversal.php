<?php
// INTENTIONALLY VULNERABLE: path is appended without canonicalization.
// This endpoint is safe only inside the isolated, disposable lab VM.
$name = substr((string)($_GET['file'] ?? 'hello.txt'), 0, 250);
$path = __DIR__ . '/files/' . $name;
header('Content-Type: text/plain; charset=utf-8');
$data = @file_get_contents($path);
if ($data === false) {
    http_response_code(404);
    echo "not found\n";
} else {
    echo $data;
}
