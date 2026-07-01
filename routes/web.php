<?php

use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    $logoCandidates = [
        'img/logo.png',
        'img/logo.jpg',
        'img/logo.jpeg',
        'img/mualimat.png',
        'img/mualimat.jpg',
        'logo.png',
        'logo.jpg',
        'img/logo-mualimat.svg',
    ];

    $logoUrl = asset('img/logo-mualimat.svg');
    foreach ($logoCandidates as $path) {
        if (file_exists(public_path($path))) {
            $logoUrl = asset($path);
            break;
        }
    }

    return view('reward.index', [
        'wsUrl'  => env('WS_URL', 'http://10.99.23.111/ws_client/Mualimat_reward/index.php'),
        'logoUrl' => $logoUrl,
    ]);
});
