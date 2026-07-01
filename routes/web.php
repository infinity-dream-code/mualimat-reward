<?php

use Illuminate\Support\Facades\Http;
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

    $tahunAkademik = [];
    try {
        $response = Http::connectTimeout(5)
            ->timeout(15)
            ->asForm()
            ->post($wsUrl, ['method' => 'getTahunAkademik']);
        $json = $response->json();
        if (is_array($json) && ($json['status'] ?? 0) === 200) {
            $list = $json['data']['tahun_akademik'] ?? [];
            if (is_array($list)) {
                $tahunAkademik = $list;
            }
        }
    } catch (\Throwable) {
        // dropdown tetap tampil kosong, user bisa refresh halaman
    }

    return view('reward.index', [
        'wsUrl'         => $wsUrl,
        'logoUrl'       => $logoUrl,
        'tahunAkademik' => $tahunAkademik,
    ]);
});
