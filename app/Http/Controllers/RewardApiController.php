<?php

namespace App\Http\Controllers;

use App\Services\WsApiService;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use InvalidArgumentException;
use Throwable;

class RewardApiController extends Controller
{
    public function __construct(private readonly WsApiService $ws)
    {
    }

    public function handle(Request $request): JsonResponse
    {
        $wsUrl = $this->ws->url();
        if ($wsUrl === '') {
            $wsEntry = base_path('ws/index.php');
            if (!is_file($wsEntry)) {
                return $this->jsonError(500, 'Konfigurasi server belum lengkap');
            }

            $this->dispatchLocalWs($request, $wsEntry);
        }

        require_once base_path('lib/SecureInput.php');

        $method = secure_validate_method(trim((string) $request->input('method', '')));
        if ($method === null) {
            return $this->jsonError(422, 'Permintaan tidak valid');
        }

        try {
            if ($method === 'login') {
                return $this->forwardForm($this->buildLoginPayload($request));
            }

            if ($method === 'getTahunAkademik') {
                return $this->handleGetTahunAkademik();
            }

            if ($method === 'getPrestasiKatalog') {
                return $this->handleGetPrestasiKatalog($request);
            }

            if ($method === 'getPrestasiSaya') {
                return $this->handleGetPrestasiSaya($request);
            }

            if ($method === 'submitPrestasi') {
                return $this->handleSubmitPrestasi($request);
            }

            return $this->jsonError(422, 'Permintaan tidak valid');
        } catch (InvalidArgumentException $e) {
            return $this->jsonError(422, $e->getMessage());
        } catch (ConnectionException) {
            return $this->jsonError(503, 'Tidak dapat terhubung ke layanan backend. Periksa WS dan koneksi database.');
        } catch (Throwable $e) {
            report($e);
            return $this->jsonError(500, 'Terjadi kesalahan sistem. Silakan coba lagi.');
        }
    }

    private function handleGetTahunAkademik(): JsonResponse
    {
        $list = $this->ws->rememberTahunAkademik();

        return response()
            ->json(['status' => 200, 'data' => ['tahun_akademik' => $list]])
            ->header('Cache-Control', 'private, max-age=300');
    }

    private function handleGetPrestasiKatalog(Request $request): JsonResponse
    {
        $token = trim((string) $request->input('token', ''));
        $data = $this->ws->rememberPrestasiKatalog($token);

        return response()
            ->json(['status' => 200, 'data' => $data])
            ->header('Cache-Control', 'private, no-store');
    }

    private function handleGetPrestasiSaya(Request $request): JsonResponse
    {
        $token = trim((string) $request->input('token', ''));
        if (!secure_validate_token_format($token)) {
            return $this->jsonError(401, 'Token JWT tidak valid');
        }

        return $this->forwardForm([
            'method' => 'getPrestasiSaya',
            'token' => $token,
        ]);
    }

    private function handleSubmitPrestasi(Request $request): JsonResponse
    {
        $token = trim((string) $request->input('token', ''));
        if (!secure_validate_token_format($token)) {
            return $this->jsonError(401, 'Token JWT tidak valid');
        }

        $fields = $this->validatePrestasiFields($request);
        $payload = [
            'method' => 'submitPrestasi',
            'token' => $token,
            'nisn' => $fields['nisn'],
            'tahun_akademik' => $fields['tahun_akademik'],
            'semester' => $fields['semester'],
            'prestasi_kategori_id' => (string) $fields['prestasi_kategori_id'],
            'prestasi_tingkat_id' => (string) $fields['prestasi_tingkat_id'],
            'prestasi_poin_id' => (string) $fields['prestasi_poin_id'],
            'keterangan' => $fields['keterangan'],
            'penyelenggara' => $fields['penyelenggara'],
            'no_sertifikat' => $fields['no_sertifikat'],
            'tanggal_pelaksanaan' => $fields['tanggal_pelaksanaan'],
            'url' => $fields['url'],
        ];
        if ($fields['id'] !== null) {
            $payload['id'] = (string) $fields['id'];
        }

        return $this->forwardForm($payload);
    }

    /**
     * @return array{id: int|null, nisn: string, tahun_akademik: string, semester: string, prestasi_kategori_id: int, prestasi_tingkat_id: int, prestasi_poin_id: int, keterangan: string, penyelenggara: string, no_sertifikat: string, tanggal_pelaksanaan: string, url: string}
     */
    private function validatePrestasiFields(Request $request): array
    {
        $idRaw = trim((string) $request->input('id', ''));
        $id = $idRaw === '' ? null : secure_validate_positive_id($idRaw);
        if ($idRaw !== '' && $id === null) {
            throw new InvalidArgumentException('Pengajuan tidak valid.');
        }

        $nisn = secure_validate_nisn((string) $request->input('nisn', ''));
        if ($nisn === null) {
            throw new InvalidArgumentException('NISN harus 10 digit angka, atau biarkan kosong.');
        }

        $tahun = secure_validate_tahun_akademik((string) $request->input('tahun_akademik', ''));
        if ($tahun === null) {
            throw new InvalidArgumentException('Tahun akademik tidak valid.');
        }

        $semester = secure_validate_semester((string) $request->input('semester', ''));
        if ($semester === null) {
            throw new InvalidArgumentException('Semester harus 1 atau 2.');
        }

        $kategoriId = secure_validate_positive_id((string) $request->input('prestasi_kategori_id', ''));
        $tingkatId = secure_validate_positive_id((string) $request->input('prestasi_tingkat_id', ''));
        $poinId = secure_validate_positive_id((string) $request->input('prestasi_poin_id', ''));
        if ($kategoriId === null || $tingkatId === null || $poinId === null) {
            throw new InvalidArgumentException('Jenis prestasi belum lengkap.');
        }

        $keterangan = secure_validate_text_field((string) $request->input('keterangan', ''), 500);
        if ($keterangan === null) {
            throw new InvalidArgumentException('Keterangan/deskripsi tidak valid (maksimal 500 karakter).');
        }

        $penyelenggara = secure_validate_text_field((string) $request->input('penyelenggara', ''), 150);
        if ($penyelenggara === null) {
            throw new InvalidArgumentException('Penyelenggara tidak valid (maksimal 150 karakter).');
        }

        $sertifikat = secure_validate_text_field((string) $request->input('no_sertifikat', ''), 80);
        if ($sertifikat === null) {
            throw new InvalidArgumentException('No sertifikat tidak valid (maksimal 80 karakter).');
        }

        $tanggal = secure_validate_tanggal((string) (
            $request->input('tanggal_pelaksanaan', '')
            ?: $request->input('tanggal_lomba', '')
            ?: $request->input('tgl_pelaksanaan', '')
        ));
        if ($tanggal === null) {
            throw new InvalidArgumentException('Tanggal pelaksanaan wajib diisi (format YYYY-MM-DD).');
        }

        $url = secure_validate_gdrive_url((string) $request->input('url', ''));
        if ($url === null) {
            throw new InvalidArgumentException('Link harus tautan Google Drive.');
        }

        return [
            'id' => $id,
            'nisn' => $nisn,
            'tahun_akademik' => $tahun,
            'semester' => $semester,
            'prestasi_kategori_id' => $kategoriId,
            'prestasi_tingkat_id' => $tingkatId,
            'prestasi_poin_id' => $poinId,
            'keterangan' => $keterangan,
            'penyelenggara' => $penyelenggara,
            'no_sertifikat' => $sertifikat,
            'tanggal_pelaksanaan' => $tanggal,
            'url' => $url,
        ];
    }

    /**
     * @return array{username: string, password: string, method: string}
     */
    private function buildLoginPayload(Request $request): array
    {
        $username = secure_validate_username((string) $request->input('username', ''));
        if ($username === null) {
            throw new InvalidArgumentException('Username tidak valid.');
        }

        $password = secure_validate_password((string) $request->input('password', ''));
        if ($password === null) {
            throw new InvalidArgumentException('Password tidak valid.');
        }

        return [
            'method' => 'login',
            'username' => $username,
            'password' => $password,
        ];
    }

    /**
     * Jalankan API di folder ws/ pada request yang sama (tanpa WS_URL remote).
     */
    private function dispatchLocalWs(Request $request, string $wsEntry): never
    {
        foreach ($request->except(['file']) as $key => $value) {
            if (is_scalar($value) || $value === null) {
                $_POST[$key] = (string) $value;
            }
        }

        $_SERVER['REQUEST_METHOD'] = 'POST';

        require $wsEntry;
        exit;
    }

    private function forwardForm(array $payload): JsonResponse
    {
        return $this->parseWsResponse($this->ws->postForm($payload));
    }

    private function parseWsResponse($response): JsonResponse
    {
        $json = $response->json();
        if (is_array($json)) {
            $status = (int) ($json['status'] ?? $response->status());
            return response()->json($json, $status > 0 ? $status : 200);
        }

        return $this->jsonError($response->status() ?: 502, 'Layanan backend tidak merespons dengan benar. Silakan coba lagi.');
    }

    private function jsonError(int $status, string $message): JsonResponse
    {
        return response()->json(['status' => $status, 'message' => $message], $status);
    }
}
