<?php

use App\Services\WsApiService;
use Illuminate\Support\Facades\Route;

Route::get('/', function (WsApiService $ws) {
    $canonical = url('/');
    $title = 'Input Prestasi Siswa | Madrasah Mu\'allimaat Muhammadiyah';
    $description = 'Portal siswa Madrasah Mu\'allimaat Muhammadiyah untuk mengirim data prestasi beserta tautan bukti Google Drive.';

    return response()
        ->view('reward.index', [
            'wsUrl' => url('/api/reward'),
            'logoUrl' => asset('img/logo-mualimat.svg'),
            'tahunAkademik' => $ws->cachedTahunAkademik(),
            'canonical' => $canonical,
            'pageTitle' => $title,
            'pageDescription' => $description,
            'siteName' => 'Madrasah Mu\'allimaat Muhammadiyah',
        ])
        ->header('Cache-Control', 'private, no-cache');
});

Route::get('/robots.txt', function () {
    $body = implode("\n", [
        'User-agent: *',
        'Allow: /',
        'Disallow: /api/',
        'Sitemap: ' . url('/sitemap.xml'),
        '',
    ]);

    return response($body, 200)->header('Content-Type', 'text/plain; charset=UTF-8');
});

Route::get('/sitemap.xml', function () {
    $loc = htmlspecialchars(url('/'), ENT_XML1 | ENT_QUOTES, 'UTF-8');
    $xml = <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>{$loc}</loc>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
</urlset>
XML;

    return response($xml, 200)->header('Content-Type', 'application/xml; charset=UTF-8');
});
