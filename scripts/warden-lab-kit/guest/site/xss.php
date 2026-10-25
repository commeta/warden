<?php
// INTENTIONALLY VULNERABLE: reflects user input without HTML escaping.
// ModSecurity/CRS should block common payloads before PHP is reached.
$q = $_GET['q'] ?? 'empty';
header('Content-Type: text/html; charset=utf-8');
echo '<!doctype html><html><head><meta charset="utf-8"><title>XSS test</title></head><body><h1>Input:</h1><div>' . $q . '</div></body></html>';
