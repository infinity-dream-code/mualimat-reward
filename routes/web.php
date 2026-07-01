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

    $wsUrl = url('/api/reward');

    return view('reward.index', [
        'wsUrl'   => $wsUrl,
        'logoUrl' => $logoUrl,
    ]);
});
