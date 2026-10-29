<?php
// Emulated Joomla! front controller.
$LAB_ENGINE = [
    'id' => 'joomla',
    'name' => 'Joomla!',
    'generator' => 'Joomla! - Open Source Content Management',
    'generator_header' => '',
    'admin' => '/administrator/',
    'cookie' => 'joomla_lab_session',
    'routes' => [
        '/administrator'      => 'admin',
        '/administrator/'     => 'admin',
        '/index.php?option=com_users' => 'admin',
        '/index.php?option=com_content' => 'sqli',
    ],
];
require __DIR__ . '/_labcore.php';
