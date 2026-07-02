<?php

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Http;
use InvalidArgumentException;
use RuntimeException;
use Throwable;

class RewardApiController extends Controller
{
    public function handle(Request $request): JsonResponse
    {
        require_once base_path('lib/SecureInput.php');

        $wsUrl = trim((string) env('WS_URL', ''));
        if ($wsUrl === '') {
            return $this->jsonError(500, 'Konfigurasi server belum lengkap');
        }

        $method = secure_validate_method(trim((string) $request->input('method', '')));
        if ($method === null) {
            return $this->jsonError(422, 'Permintaan tidak valid');
        }

        try {
            if ($method === 'login') {
                return $this->forwardToWs($wsUrl, $this->buildLoginPayload($request));
            }

            if ($method === 'getTahunAkademik') {
                return $this->forwardToWs($wsUrl, ['method' => 'getTahunAkademik']);
            }

            if ($method === 'submitPrestasi') {
                return $this->handleSubmitPrestasi($request, $wsUrl);
            }

            return $this->jsonError(422, 'Permintaan tidak valid');
        } catch (InvalidArgumentException $e) {
            return $this->jsonError(422, $e->getMessage());
        } catch (Throwable) {
            return $this->jsonError(500, 'Terjadi kesalahan sistem. Silakan coba lagi.');
        }
    }

    private function handleSubmitPrestasi(Request $request, string $wsUrl): JsonResponse
    {
        if (!$request->hasFile('file')) {
            return $this->jsonError(422, 'File tidak diterima. Pastikan format PNG/JPG/PDF dan maksimal 2MB.');
        }

        $file = $request->file('file');
        if ($file === null || !$file->isValid()) {
            return $this->jsonError(422, 'File upload tidak valid');
        }

        $token = trim((string) $request->input('token', ''));
        if (!secure_validate_token_format($token)) {
            return $this->jsonError(401, 'Token JWT tidak valid');
        }

        $decoded = $this->decodeToken($token);
        if ($decoded === null) {
            return $this->jsonError(401, 'Token JWT tidak valid');
        }

        $nocust = trim((string) ($decoded['nocust'] ?? ''));
        if (!secure_validate_nocust($nocust)) {
            return $this->jsonError(401, 'Sesi tidak valid, silakan login ulang');
        }

        $fields = $this->validatePrestasiFields($request);
        $stored = $this->storeUploadFile($file, $nocust, $fields['jenis_prestasi'], $fields['keterangan']);

        $payload = [
            'method' => 'submitPrestasi',
            'token' => $token,
            'jenis_prestasi' => $fields['jenis_prestasi'],
            'keterangan' => $fields['keterangan'],
            'nilai_penghargaan' => $fields['nilai_penghargaan'],
            'tahun_akademik' => $fields['tahun_akademik'],
            'url' => $stored['url'],
        ];

        $response = Http::connectTimeout(5)
            ->timeout(20)
            ->retry(1, 150)
            ->asMultipart()
            ->attach('file', fopen($stored['path'], 'r'), $stored['name'])
            ->post($wsUrl, $payload);

        return $this->parseWsResponse($response);
    }

    /**
     * @return array{jenis_prestasi: string, keterangan: string, nilai_penghargaan: string, tahun_akademik: string}
     */
    private function validatePrestasiFields(Request $request): array
    {
        $jenis = secure_validate_text_field((string) $request->input('jenis_prestasi', ''), 150);
        if ($jenis === null) {
            throw new InvalidArgumentException('Jenis prestasi tidak valid (maksimal 150 karakter).');
        }

        $keterangan = secure_validate_text_field((string) $request->input('keterangan', ''), 500);
        if ($keterangan === null) {
            throw new InvalidArgumentException('Keterangan tidak valid (maksimal 500 karakter).');
        }

        $nilai = secure_validate_nilai_penghargaan((string) $request->input('nilai_penghargaan', ''));
        if ($nilai === null) {
            throw new InvalidArgumentException('Nilai penghargaan tidak valid.');
        }

        $tahun = secure_validate_tahun_akademik((string) $request->input('tahun_akademik', ''));
        if ($tahun === null) {
            throw new InvalidArgumentException('Tahun akademik tidak valid.');
        }

        return [
            'jenis_prestasi' => $jenis,
            'keterangan' => $keterangan,
            'nilai_penghargaan' => $nilai,
            'tahun_akademik' => $tahun,
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
   * @return array{path: string, name: string, url: string}
   */
    private function storeUploadFile(UploadedFile $file, string $nocust, string $jenis, string $ket): array
    {
        $tmpPath = $file->getPathname();
        $inspected = secure_inspect_upload(
            $tmpPath,
            (string) $file->getClientOriginalName(),
            (int) $file->getSize()
        );

        if (!$inspected['valid']) {
            throw new InvalidArgumentException($inspected['error'] !== '' ? $inspected['error'] : 'File upload tidak valid');
        }

        $fileName = secure_build_upload_filename($jenis, $ket, $inspected['ext']);
        $folder = public_path('uploads/' . $nocust);
        if (!is_dir($folder) && !mkdir($folder, 0755, true) && !is_dir($folder)) {
            throw new RuntimeException('UPLOAD_DIR_ERROR');
        }

        $file->move($folder, $fileName);
        $fullPath = $folder . DIRECTORY_SEPARATOR . $fileName;

        return [
            'path' => $fullPath,
            'name' => $fileName,
            'url' => url('uploads/' . $nocust . '/' . $fileName),
        ];
    }

    private function forwardToWs(string $wsUrl, array $payload): JsonResponse
    {
        $response = Http::connectTimeout(5)
            ->timeout(20)
            ->retry(1, 150)
            ->asForm()
            ->acceptJson()
            ->post($wsUrl, $this->normalizePayload($payload));

        return $this->parseWsResponse($response);
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

    private function decodeToken(string $token): ?array
    {
        try {
            require_once base_path('lib/jwt.php');
            $jwt = new \JWT();
            $decoded = $jwt->decode($token, (string) env('JWT_KEY'), ['HS256']);
            return is_array($decoded) ? $decoded : null;
        } catch (Throwable) {
            return null;
        }
    }

    private function jsonError(int $status, string $message): JsonResponse
    {
        return response()->json(['status' => $status, 'message' => $message], $status);
    }
}
