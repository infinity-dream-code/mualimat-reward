<?php

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Http;
use RuntimeException;
use Throwable;

class RewardApiController extends Controller
{
    public function handle(Request $request): JsonResponse
    {
        $wsUrl = trim((string) env("WS_URL", ""));
        if ($wsUrl === "") {
            return response()->json([
                "status" => 500,
                "message" => "WS_URL belum diatur di .env",
            ], 500);
        }

        $method = trim((string) $request->input("method", ""));
        if ($method === "") {
            return response()->json([
                "status" => 422,
                "message" => "Method wajib diisi",
            ], 422);
        }

        try {
            if ($method === "submitPrestasi" && !$request->hasFile("file")) {
                return response()->json([
                    "status" => 422,
                    "message" => "File tidak diterima server. Cek upload_max_filesize/post_max_size PHP dan nginx client_max_body_size.",
                ], 422);
            }

            $payload = $this->normalizePayload($request->except("file"));
            $payload["method"] = $method;

            if ($method === "submitPrestasi" && $request->hasFile("file")) {
                $file = $request->file("file");
                if ($file === null || !$file->isValid()) {
                    return response()->json([
                        "status" => 422,
                        "message" => "File upload tidak valid",
                    ], 422);
                }

                $token = (string) $request->input("token", "");
                $decoded = $this->decodeToken($token);
                if ($decoded === null) {
                    return response()->json([
                        "status" => 401,
                        "message" => "Token JWT tidak valid",
                    ], 401);
                }

                $nocust = trim((string) ($decoded["nocust"] ?? ""));
                if ($nocust === "") {
                    return response()->json([
                        "status" => 401,
                        "message" => "Sesi tidak valid, silakan login ulang",
                    ], 401);
                }

                $jenis = trim((string) $request->input("jenis_prestasi", ""));
                $ket = trim((string) $request->input("keterangan", ""));
                $stored = $this->storeUploadFile($file, $nocust, $jenis, $ket);

                $payload["url"] = $stored["url"];
                $payload["token"] = $token;
                $payload["jenis_prestasi"] = $jenis;
                $payload["keterangan"] = $ket;
                $payload["nilai_penghargaan"] = trim((string) $request->input("nilai_penghargaan", ""));
                $payload["tahun_akademik"] = trim((string) $request->input("tahun_akademik", ""));

                $response = Http::connectTimeout(5)
                    ->timeout(20)
                    ->retry(1, 150)
                    ->asMultipart()
                    ->attach("file", fopen($stored["path"], "r"), $stored["name"])
                    ->post($wsUrl, $payload);
            } else {
                $response = Http::connectTimeout(5)
                    ->timeout(20)
                    ->retry(1, 150)
                    ->asForm()
                    ->acceptJson()
                    ->post($wsUrl, $payload);
            }

            $json = $response->json();
            if (is_array($json)) {
                $status = (int) ($json["status"] ?? $response->status());
                return response()->json($json, $status > 0 ? $status : 200);
            }

            $raw = preg_replace('/\s+/', ' ', (string) $response->body());
            $raw = trim((string) $raw);
            $raw = mb_substr($raw, 0, 220);

            return response()->json([
                "status" => $response->status(),
                "message" => "Respons WS bukan JSON | HTTP: " . $response->status() . " | RAW: " . $raw,
                "raw" => $response->body(),
            ], $response->status());
        } catch (Throwable $e) {
            return response()->json([
                "status" => 500,
                "message" => $e->getMessage(),
            ], 500);
        }
    }

  /**
   * @return array{path: string, name: string, url: string}
   */
    private function storeUploadFile(UploadedFile $file, string $nocust, string $jenis, string $ket): array
    {
        if ($file->getSize() > 2 * 1024 * 1024) {
            throw new RuntimeException("Ukuran file maksimal 2MB");
        }

        $ext = strtolower((string) $file->getClientOriginalExtension());
        if (!in_array($ext, ["png", "jpg", "jpeg", "pdf"], true)) {
            throw new RuntimeException("Format file harus png/jpg/jpeg/pdf");
        }

        $mime = strtolower((string) $file->getMimeType());
        if (!in_array($mime, ["image/png", "image/jpeg", "application/pdf"], true)) {
            throw new RuntimeException("Tipe file tidak valid");
        }

        $base = $this->slugify($jenis) . "_" . $this->slugify($ket);
        $base = trim($base, "_");
        if ($base === "") {
            $base = "prestasi";
        }

        $fileName = $base . "_" . time() . "." . $ext;
        $folder = public_path("uploads/" . $nocust);
        if (!is_dir($folder) && !mkdir($folder, 0755, true) && !is_dir($folder)) {
            throw new RuntimeException("Gagal membuat folder upload: " . $folder);
        }

        $file->move($folder, $fileName);
        $fullPath = $folder . DIRECTORY_SEPARATOR . $fileName;

        return [
            "path" => $fullPath,
            "name" => $fileName,
            "url"  => url("uploads/" . $nocust . "/" . $fileName),
        ];
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

    private function slugify(string $value): string
    {
        $value = strtolower(trim($value));
        $value = preg_replace('/[^a-z0-9]+/', "_", $value);
        return trim((string) $value, "_");
    }

    private function decodeToken(string $token): ?array
    {
        if ($token === "") {
            return null;
        }

        try {
            require_once base_path("lib/jwt.php");
            $jwt = new \JWT();
            $decoded = $jwt->decode($token, (string) env("JWT_KEY"), ["HS256"]);
            return is_array($decoded) ? $decoded : null;
        } catch (Throwable) {
            return null;
        }
    }
}
