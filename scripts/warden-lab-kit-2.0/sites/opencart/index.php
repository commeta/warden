<?php
// Emulated OpenCart storefront front controller.
$LAB_ENGINE = [
    'id' => 'opencart',
    'name' => 'OpenCart',
    'generator' => 'OpenCart 4.0.2.3',
    'generator_header' => '',
    'admin' => '/admin/',
    'cookie' => 'OCSESSID_lab',
    'routes' => [
        '/admin'              => 'admin',
        '/admin/'             => 'admin',
        '/index.php?route=product/product' => 'sqli',
        '/index.php?route=account/login'   => 'admin',
        '/index.php?route=common/filemanager' => 'upload',
    ],
];
require __DIR__ . '/_labcore.php';
