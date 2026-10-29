<?php
// Emulated 1C-Bitrix front controller.
$LAB_ENGINE = [
    'id' => 'bitrix',
    'name' => '1C-Bitrix',
    'generator' => '1C-Bitrix Site Manager',
    'generator_header' => '',
    'admin' => '/bitrix/admin/',
    'cookie' => 'BITRIX_SM_LAB',
    'routes' => [
        '/bitrix/admin'       => 'admin',
        '/bitrix/admin/'      => 'admin',
        '/bitrix/tools/'      => 'upload',
        '/bitrix/admin/1cv8_runner.php' => 'admin_save',
    ],
];
require __DIR__ . '/_labcore.php';
