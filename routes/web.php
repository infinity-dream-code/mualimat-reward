<?php

use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('reward.index', [
        'wsUrl' => env('WS_URL', 'http://10.99.23.111/ws_client/Mualimat_reward/index.php'),
    ]);
});
