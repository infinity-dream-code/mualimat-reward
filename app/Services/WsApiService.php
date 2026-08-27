<?php

namespace App\Services;

use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use RuntimeException;

class WsApiService
{
    public const TAHUN_CACHE_KEY = 'ws.tahun_akademik';

    public const TAHUN_CACHE_TTL = 21600;

    public const KATALOG_CACHE_KEY = 'ws.prestasi_katalog.v3';

    public const KATALOG_CACHE_TTL = 60;

    private const CONNECT_TIMEOUT = 20;

    private const REQUEST_TIMEOUT = 90;

    public function url(): string
    {
        return trim((string) config('services.ws.url', ''));
    }

    /**
     * @return list<string>
     */
    public function cachedTahunAkademik(): array
    {
        $list = Cache::get(self::TAHUN_CACHE_KEY, []);

        return $this->normalizeTahunList($list);
    }

    /**
     * @return list<string>
     */
    public function rememberTahunAkademik(): array
    {
        $cached = $this->cachedTahunAkademik();
        if ($cached !== []) {
            return $cached;
        }

        $response = $this->postForm(['method' => 'getTahunAkademik']);
        $json = $response->json();
        $list = is_array($json) ? ($json['data']['tahun_akademik'] ?? []) : [];
        $list = $this->normalizeTahunList($list);

        if ($list !== []) {
            $ttl = (int) config('services.ws.tahun_cache_ttl', self::TAHUN_CACHE_TTL);
            Cache::put(self::TAHUN_CACHE_KEY, $list, $ttl > 0 ? $ttl : self::TAHUN_CACHE_TTL);
        }

        return $list;
    }

    /**
     * @return array{kategori: list<array<string, mixed>>, tingkat: list<array<string, mixed>>, poin: list<array<string, mixed>>}
     */
    public function rememberPrestasiKatalog(?string $token = null): array
    {
        $token = trim((string) $token);
        $code01 = $this->claimFromToken($token, 'code01');
        $unit = $this->claimFromToken($token, 'unit');

        $cached = Cache::get(self::KATALOG_CACHE_KEY);
        $usable = is_array($cached)
            && isset($cached['kategori'], $cached['tingkat'], $cached['poin'])
            && $this->katalogHasUnitColumn($cached['kategori']);

        if (! $usable) {
            $cached = $this->pullKatalog('');
            if ($cached['kategori'] !== [] && $this->katalogHasUnitColumn($cached['kategori'])) {
                Cache::put(self::KATALOG_CACHE_KEY, $cached, self::KATALOG_CACHE_TTL);
            } elseif ($token !== '') {
                $cached = $this->pullKatalog($token);
            }
        }

        return $this->filterKatalogByUnit($cached, $code01, $unit);
    }

    /**
     * @return array{kategori: list<array<string, mixed>>, tingkat: list<array<string, mixed>>, poin: list<array<string, mixed>>}
     */
    private function pullKatalog(string $token): array
    {
        $payload = ['method' => 'getPrestasiKatalog'];
        if ($token !== '') {
            $payload['token'] = $token;
        }
        $response = $this->postForm($payload);
        $json = $response->json();
        $data = is_array($json) ? ($json['data'] ?? []) : [];

        return [
            'kategori' => is_array($data['kategori'] ?? null) ? $data['kategori'] : [],
            'tingkat' => is_array($data['tingkat'] ?? null) ? $data['tingkat'] : [],
            'poin' => is_array($data['poin'] ?? null) ? $data['poin'] : [],
        ];
    }

    /**
     * @param  array{kategori: list<array<string, mixed>>, tingkat: list<array<string, mixed>>, poin: list<array<string, mixed>>}  $data
     * @return array{kategori: list<array<string, mixed>>, tingkat: list<array<string, mixed>>, poin: list<array<string, mixed>>}
     */
    public function filterKatalogByUnit(array $data, string $code01, string $unit = ''): array
    {
        $code01 = trim($code01);
        $unit = trim($unit);
        if ($code01 === '' && $unit === '') {
            return $data;
        }

        $kategori = [];
        $katIds = [];
        foreach ($data['kategori'] as $row) {
            if (! is_array($row) || ! $this->kategoriVisibleForUnit($this->rowCode01($row), $code01, $unit)) {
                continue;
            }
            $kategori[] = $row;
            $katIds[(int) ($row['id'] ?? 0)] = true;
        }

        $tingkat = [];
        $lvlIds = [];
        foreach ($data['tingkat'] as $row) {
            if (! is_array($row) || ! isset($katIds[(int) ($row['kategori_id'] ?? 0)])) {
                continue;
            }
            $tingkat[] = $row;
            $lvlIds[(int) ($row['id'] ?? 0)] = true;
        }

        $poin = [];
        foreach ($data['poin'] as $row) {
            if (! is_array($row) || ! isset($lvlIds[(int) ($row['tingkat_id'] ?? 0)])) {
                continue;
            }
            $poin[] = $row;
        }

        return [
            'kategori' => $kategori,
            'tingkat' => $tingkat,
            'poin' => $poin,
        ];
    }

    /**
     * @param  list<array<string, mixed>>  $kategori
     */
    private function katalogHasUnitColumn(array $kategori): bool
    {
        foreach ($kategori as $row) {
            if (is_array($row) && (array_key_exists('code01', $row) || array_key_exists('CODE01', $row))) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  array<string, mixed>  $row
     */
    private function rowCode01(array $row): mixed
    {
        if (array_key_exists('code01', $row)) {
            return $row['code01'];
        }
        if (array_key_exists('CODE01', $row)) {
            return $row['CODE01'];
        }

        return null;
    }

    private function kategoriVisibleForUnit(mixed $rowCode01, string $siswaCode01, string $siswaUnit = ''): bool
    {
        $rowCode01 = trim((string) ($rowCode01 ?? ''));
        if ($rowCode01 === '') {
            return true;
        }
        if ($siswaCode01 === '' && $siswaUnit === '') {
            return true;
        }

        return $this->unitKeyEquals($rowCode01, $siswaCode01) || $this->unitKeyEquals($rowCode01, $siswaUnit);
    }

    private function unitKeyEquals(string $a, string $b): bool
    {
        $norm = static function (string $value): string {
            return str_replace([' ', '.', '_'], '', strtoupper(trim($value)));
        };
        $a = $norm($a);
        $b = $norm($b);

        return $a !== '' && $b !== '' && $a === $b;
    }

    private function claimFromToken(string $token, string $claim): string
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return '';
        }
        $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
        if (! is_array($payload)) {
            return '';
        }

        return trim((string) ($payload[$claim] ?? ''));
    }

    public function postForm(array $payload): Response
    {
        return $this->client()
            ->asForm()
            ->post($this->requireUrl(), $this->normalizePayload($payload));
    }

    public function postMultipart(array $payload, string $fileContents, string $fileName): Response
    {
        return $this->client()
            ->asMultipart()
            ->attach('file', $fileContents, $fileName)
            ->post($this->requireUrl(), $this->normalizePayload($payload));
    }

    private function requireUrl(): string
    {
        $url = $this->url();
        if ($url === '') {
            throw new RuntimeException('WS_URL_EMPTY');
        }

        return $url;
    }

    private function client()
    {
        set_time_limit(120);

        return Http::connectTimeout(self::CONNECT_TIMEOUT)
            ->timeout(self::REQUEST_TIMEOUT)
            ->acceptJson()
            ->withHeaders([
                'Accept-Encoding' => 'gzip, deflate',
                'Connection' => 'keep-alive',
            ])
            ->withOptions([
                'http_errors' => false,
                'decode_content' => true,
            ]);
    }

    /**
     * @return list<string>
     */
    private function normalizeTahunList(mixed $list): array
    {
        if (!is_array($list)) {
            return [];
        }

        $normalized = [];
        foreach ($list as $item) {
            if (!is_string($item) && !is_numeric($item)) {
                continue;
            }
            $value = trim((string) $item);
            if (preg_match('/^\d{4}\/\d{4}$/', $value) !== 1) {
                continue;
            }
            $normalized[] = $value;
        }

        return array_values(array_unique($normalized));
    }

    /**
     * @return array<string, string>
     */
    private function normalizePayload(array $payload): array
    {
        $normalized = [];
        foreach ($payload as $key => $value) {
            if (is_scalar($value) || $value === null) {
                $normalized[$key] = (string) $value;
            }
        }

        return $normalized;
    }
}
