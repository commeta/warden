<?php
// Emulated Drupal front controller.
$LAB_ENGINE = [
    'id' => 'drupal',
    'name' => 'Drupal',
    'generator' => 'Drupal 10 (https://www.drupal.org)',
    'generator_header' => 'Drupal 10',
    'admin' => '/user/login',
    'cookie' => 'SESS_lab',
    'routes' => [
        '/user/login'         => 'admin',
        '/user'               => 'admin',
        '/node/add'           => 'admin_save',
        '/sites/default/files/' => 'traversal',
        '/?q=node'            => 'sqli',
    ],
];
require __DIR__ . '/_labcore.php';
