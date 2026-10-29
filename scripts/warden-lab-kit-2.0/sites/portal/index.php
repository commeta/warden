<?php
// The Warden Lab portal: the default vhost. Lists the emulated sites and the
// microservices (which are reverse-proxied here under /svc/<name>/), and
// carries the shared /lab/* targets like any other site.
$LAB_ENGINE = [
    'id' => 'portal',
    'name' => 'Warden Lab Portal',
    'generator' => 'Warden Lab Kit 2.0',
    'generator_header' => '',
    'admin' => '/',
    'cookie' => '',
    'routes' => [],
];
$m = @include __DIR__ . '/_manifest.php';
if (is_array($m)) {
    $GLOBALS['LAB_PORTAL'] = $m;
}
require __DIR__ . '/_labcore.php';
