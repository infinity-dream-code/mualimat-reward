<?php
date_default_timezone_set('Asia/Jakarta');

require __DIR__ . '/config/jwt.php';

$payload = [
    
];

$key = '53c2f9aariasb60akenoa3dc29b60c3e1gremorye3c1701f4355fa4';

$jwt = new JWT();
$token = $jwt->encode($payload, $key, 'HS256');

header('Content-Type: text/plain; charset=utf-8');
echo $token;
