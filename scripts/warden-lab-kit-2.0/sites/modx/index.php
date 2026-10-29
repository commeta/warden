<?php
// Emulated MODX Revolution front controller.
$LAB_ENGINE = [
    'id' => 'modx',
    'name' => 'MODX Revolution',
    'generator' => 'MODX Revolution 2.8.6-pl',
    'generator_header' => '',
    'admin' => '/manager/',
    'cookie' => 'modx_lab_session',
    'routes' => [
        '/manager'            => 'admin',
        '/manager/'           => 'admin',
        '/core'               => 'notfound',
        '/connectors/'        => 'admin_save',
        '/assets/components/' => 'traversal',
    ],
];
require __DIR__ . '/_labcore.php';
