<?php
// Signals command-injection-like input without calling a shell or executing commands.
$cmd = substr((string)($_GET['cmd'] ?? ''), 0, 200);
header('Content-Type: text/plain; charset=utf-8');
echo "Command execution is intentionally disabled in this route.\nInput received: " . $cmd . "\n";
