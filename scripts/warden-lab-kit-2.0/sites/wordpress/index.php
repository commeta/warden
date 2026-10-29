<?php
// Emulated WordPress front controller for the Warden Lab Kit.
$LAB_ENGINE = [
    'id' => 'wordpress',
    'name' => 'WordPress',
    'generator' => 'WordPress 6.6.2',
    'generator_header' => '',
    'admin' => '/wp-admin/',
    'cookie' => 'wordpress_logged_in_lab',
    'routes' => [
        '/wp-login.php'       => 'admin',
        '/wp-admin'           => 'admin',
        '/wp-admin/post.php'  => 'admin_save',
        '/xmlrpc.php'         => 'info',
        '/?author=1'          => 'sqli',
    ],
];
require __DIR__ . '/_labcore.php';
